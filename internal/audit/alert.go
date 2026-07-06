package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Notifier emits security alerts for anomalous activity.
type Notifier interface {
	LoginFailureThreshold(userID uuid.UUID, ip string, count int)
	NewDevice(userID uuid.UUID, userAgent string)
}

// SlogNotifier logs alerts via slog (default Phase 5 implementation).
type SlogNotifier struct {
	Log *slog.Logger
}

func (n *SlogNotifier) LoginFailureThreshold(userID uuid.UUID, ip string, count int) {
	n.Log.Warn("security alert: repeated login failures",
		"user_id", userID,
		"ip", ip,
		"count", count,
		"window_minutes", 15,
	)
}

func (n *SlogNotifier) NewDevice(userID uuid.UUID, userAgent string) {
	n.Log.Info("security notice: login from new device",
		"user_id", userID,
		"user_agent", userAgent,
	)
}

// Tracker records login failures and raises alerts when thresholds are exceeded.
type Tracker struct {
	mu       sync.Mutex
	failures map[uuid.UUID][]time.Time
	notifier Notifier
	limit    int
	window   time.Duration
}

// NewTracker creates a failure tracker with default thresholds.
func NewTracker(notifier Notifier) *Tracker {
	return &Tracker{
		failures: make(map[uuid.UUID][]time.Time),
		notifier: notifier,
		limit:    5,
		window:   15 * time.Minute,
	}
}

// RecordLoginFailure increments the failure counter and alerts if over limit.
func (t *Tracker) RecordLoginFailure(userID uuid.UUID, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-t.window)
	events := t.failures[userID]
	pruned := events[:0]
	for _, ts := range events {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	pruned = append(pruned, time.Now())
	t.failures[userID] = pruned
	if len(pruned) >= t.limit {
		t.notifier.LoginFailureThreshold(userID, ip, len(pruned))
	}
}

// ResetFailures clears failures after a successful login.
func (t *Tracker) ResetFailures(userID uuid.UUID) {
	t.mu.Lock()
	delete(t.failures, userID)
	t.mu.Unlock()
}

// HashUserAgent returns a stable hash for device tracking.
func HashUserAgent(ua string) []byte {
	if ua == "" {
		return nil
	}
	h := sha256.Sum256([]byte(ua))
	return h[:]
}

// FormatUAHash encodes the hash for logging.
func FormatUAHash(h []byte) string {
	return hex.EncodeToString(h)
}
