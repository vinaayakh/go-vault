package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vinaayakh/secure-vault/internal/storage"
)

const (
	rawTokenBytes     = 32
	AccessCookieName  = "vault_access"
	RefreshCookieName = "vault_refresh"
	RefreshCookiePath = "/api/auth/refresh"

	// loginIPLimit: max failed attempts per IP per window.
	loginIPLimit  = 10
	loginIPWindow = 15 * time.Minute

	// loginAccountLimit: max failed attempts per account per window.
	loginAccountLimit  = 5
	loginAccountWindow = 15 * time.Minute

	// registerIPLimit: cap mass-registration abuse per IP.
	registerIPLimit  = 5
	registerIPWindow = time.Hour
)

// CookieName is deprecated; use AccessCookieName.
const CookieName = AccessCookieName

// Manager handles session lifecycle, rate limiting, and account lockout.
type Manager struct {
	sessions   *storage.SessionsRepo
	loginIP    *RateLimiter
	loginAcct  *RateLimiter
	registerIP *RateLimiter
	lockout    *LockoutTracker
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewManager creates a Manager backed by the given sessions repository.
func NewManager(sessions *storage.SessionsRepo, accessTTL, refreshTTL time.Duration) *Manager {
	return &Manager{
		sessions:   sessions,
		loginIP:    newRateLimiter(loginIPLimit, loginIPWindow),
		loginAcct:  newRateLimiter(loginAccountLimit, loginAccountWindow),
		registerIP: newRateLimiter(registerIPLimit, registerIPWindow),
		lockout:    newLockoutTracker(),
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

// AccessTTL returns the configured access-token lifetime.
func (m *Manager) AccessTTL() time.Duration { return m.accessTTL }

// RefreshTTL returns the configured refresh-token lifetime.
func (m *Manager) RefreshTTL() time.Duration { return m.refreshTTL }

// IsLoginLocked reports whether the email is temporarily locked out.
func (m *Manager) IsLoginLocked(email string) bool {
	return m.lockout.IsLocked(email)
}

// RecordLoginFailure records a failed login and returns the backoff delay.
func (m *Manager) RecordLoginFailure(email string) time.Duration {
	return m.lockout.RecordFailure(email)
}

// CheckLoginLimit returns true if the request is within allowed limits for the
// given IP and email.
func (m *Manager) CheckLoginLimit(ip, email string) bool {
	return m.loginIP.Allow(ip) && m.loginAcct.Allow(email)
}

// ResetLoginLimit clears rate-limit and lockout counters after successful login.
func (m *Manager) ResetLoginLimit(ip, email string) {
	m.loginIP.Reset(ip)
	m.loginAcct.Reset(email)
	m.lockout.Reset(email)
}

// CheckRegisterLimit returns true if this IP is within the registration limit.
func (m *Manager) CheckRegisterLimit(ip string) bool {
	return m.registerIP.Allow(ip)
}

// CreateSessionPair mints access + refresh tokens, persists their hashes, and
// returns the raw hex tokens for cookie placement.
func (m *Manager) CreateSessionPair(ctx context.Context, userID uuid.UUID) (accessRaw, refreshRaw string, err error) {
	accessRaw, err = generateToken()
	if err != nil {
		return "", "", fmt.Errorf("generate access token: %w", err)
	}
	refreshRaw, err = generateToken()
	if err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}

	now := time.Now()
	_, err = m.sessions.CreatePair(ctx, userID,
		hashToken(accessRaw), now.Add(m.accessTTL),
		hashToken(refreshRaw), now.Add(m.refreshTTL),
	)
	if err != nil {
		return "", "", fmt.Errorf("persist session: %w", err)
	}
	return accessRaw, refreshRaw, nil
}

// ValidateAccess looks up the session by access token hash and checks expiry.
func (m *Manager) ValidateAccess(ctx context.Context, accessRaw string) (*storage.Session, error) {
	sess, err := m.sessions.GetByAccessHash(ctx, hashToken(accessRaw))
	if errors.Is(err, storage.ErrNotFound) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("look up session: %w", err)
	}
	if time.Now().After(sess.AccessExpiresAt) {
		return nil, ErrSessionInvalid
	}
	return sess, nil
}

// RefreshSession validates the refresh token, rotates both hashes, and returns
// new raw tokens. The previous refresh token is invalidated atomically.
func (m *Manager) RefreshSession(ctx context.Context, refreshRaw string) (newAccess, newRefresh string, err error) {
	sess, err := m.sessions.GetByRefreshHash(ctx, hashToken(refreshRaw))
	if errors.Is(err, storage.ErrNotFound) {
		return "", "", ErrSessionInvalid
	}
	if err != nil {
		return "", "", fmt.Errorf("look up refresh session: %w", err)
	}
	if time.Now().After(sess.RefreshExpiresAt) {
		return "", "", ErrSessionInvalid
	}

	newAccess, err = generateToken()
	if err != nil {
		return "", "", fmt.Errorf("generate access token: %w", err)
	}
	newRefresh, err = generateToken()
	if err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}

	now := time.Now()
	_, err = m.sessions.RotateTokens(ctx, sess.ID,
		hashToken(newAccess), now.Add(m.accessTTL),
		hashToken(newRefresh), now.Add(m.refreshTTL),
	)
	if err != nil {
		return "", "", fmt.Errorf("rotate session tokens: %w", err)
	}
	return newAccess, newRefresh, nil
}

// RevokeSession deletes the session identified by the access token.
func (m *Manager) RevokeSession(ctx context.Context, accessRaw string) error {
	if err := m.sessions.DeleteByAccessHash(ctx, hashToken(accessRaw)); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeAllSessions deletes every session for a user.
func (m *Manager) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if err := m.sessions.DeleteAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}
	return nil
}

// ErrSessionInvalid is returned when a session token is absent, expired, or
// not found. Callers must not distinguish between these cases.
var ErrSessionInvalid = errors.New("session invalid or expired")

func generateToken() (string, error) {
	b := make([]byte, rawTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(rawToken string) []byte {
	h := sha256.Sum256([]byte(rawToken))
	return h[:]
}
