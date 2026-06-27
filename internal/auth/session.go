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
	rawTokenBytes = 32
	cookieName    = "vault_session"

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

// CookieName is the session cookie name used by the API layer.
const CookieName = cookieName

// Manager handles session lifecycle and rate limiting.
type Manager struct {
	sessions   *storage.SessionsRepo
	loginIP    *RateLimiter
	loginAcct  *RateLimiter
	registerIP *RateLimiter
	duration   time.Duration
}

// NewManager creates a Manager backed by the given sessions repository.
func NewManager(sessions *storage.SessionsRepo, duration time.Duration) *Manager {
	return &Manager{
		sessions:   sessions,
		loginIP:    newRateLimiter(loginIPLimit, loginIPWindow),
		loginAcct:  newRateLimiter(loginAccountLimit, loginAccountWindow),
		registerIP: newRateLimiter(registerIPLimit, registerIPWindow),
		duration:   duration,
	}
}

// CheckLoginLimit returns true if the request is within allowed limits for the
// given IP and email. Both the per-IP and per-account windows must have capacity.
// The attempt is recorded only when both checks pass (fail-open on the recording
// side is fine — we never want to lock out the legitimate user via our own counter).
func (m *Manager) CheckLoginLimit(ip, email string) bool {
	return m.loginIP.Allow(ip) && m.loginAcct.Allow(email)
}

// ResetLoginLimit clears the counters for a key pair after a successful login
// so the user is not penalized for earlier mistakes.
func (m *Manager) ResetLoginLimit(ip, email string) {
	m.loginIP.Reset(ip)
	m.loginAcct.Reset(email)
}

// CheckRegisterLimit returns true if this IP is within the registration limit.
func (m *Manager) CheckRegisterLimit(ip string) bool {
	return m.registerIP.Allow(ip)
}

// CreateSession mints a new session for userID, persists the token hash, and
// returns the raw hex token (to be placed in the session cookie).
func (m *Manager) CreateSession(ctx context.Context, userID uuid.UUID) (string, error) {
	raw, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}

	hash := hashToken(raw)
	expiresAt := time.Now().Add(m.duration)

	if _, err := m.sessions.Create(ctx, userID, hash, expiresAt); err != nil {
		return "", fmt.Errorf("persist session: %w", err)
	}

	return raw, nil
}

// ValidateSession looks up the session by token hash, checks expiry, and returns
// the session record. Returns ErrSessionInvalid for any failure so callers
// cannot distinguish not-found from expired (no information leak).
func (m *Manager) ValidateSession(ctx context.Context, rawToken string) (*storage.Session, error) {
	hash := hashToken(rawToken)

	sess, err := m.sessions.GetByTokenHash(ctx, hash)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("look up session: %w", err)
	}

	if time.Now().After(sess.ExpiresAt) {
		_ = m.sessions.Delete(ctx, hash) // best-effort cleanup
		return nil, ErrSessionInvalid
	}

	return sess, nil
}

// RevokeSession deletes a single session (logout).
func (m *Manager) RevokeSession(ctx context.Context, rawToken string) error {
	hash := hashToken(rawToken)
	if err := m.sessions.Delete(ctx, hash); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeAllSessions deletes every session for a user (account deletion or
// "sign out everywhere").
func (m *Manager) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if err := m.sessions.DeleteAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}
	return nil
}

// ErrSessionInvalid is returned when a session token is absent, expired, or
// not found. Callers must not distinguish between these cases.
var ErrSessionInvalid = errors.New("session invalid or expired")

// generateToken returns a 32-byte cryptographically random hex string.
func generateToken() (string, error) {
	b := make([]byte, rawTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashToken returns the SHA-256 hash of a raw hex token for safe DB storage.
func hashToken(rawToken string) []byte {
	h := sha256.Sum256([]byte(rawToken))
	return h[:]
}
