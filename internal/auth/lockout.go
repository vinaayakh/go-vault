package auth

import (
	"sync"
	"time"
)

const (
	lockoutFailureThreshold = 5
	lockoutDuration         = 15 * time.Minute
	lockoutWindow           = 15 * time.Minute
	maxBackoff              = 8 * time.Second
	backoffBase             = 250 * time.Millisecond
)

type failureRecord struct {
	failures    int
	firstFail   time.Time
	lockedUntil time.Time
}

// LockoutTracker tracks consecutive login failures per email and applies
// account lockout after repeated failures within a sliding window.
type LockoutTracker struct {
	mu      sync.Mutex
	records map[string]*failureRecord
}

func newLockoutTracker() *LockoutTracker {
	return &LockoutTracker{records: make(map[string]*failureRecord)}
}

// IsLocked returns true when the email is temporarily locked out.
func (l *LockoutTracker) IsLocked(email string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := l.records[email]
	if rec == nil {
		return false
	}
	now := time.Now()
	if rec.lockedUntil.After(now) {
		return true
	}
	if rec.lockedUntil.Before(now) && !rec.lockedUntil.IsZero() {
		delete(l.records, email)
	}
	return false
}

// RecordFailure increments the failure counter and may set a lockout deadline.
func (l *LockoutTracker) RecordFailure(email string) time.Duration {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	rec := l.records[email]
	if rec == nil {
		rec = &failureRecord{firstFail: now}
		l.records[email] = rec
	}

	if now.Sub(rec.firstFail) > lockoutWindow {
		rec.failures = 0
		rec.firstFail = now
		rec.lockedUntil = time.Time{}
	}

	rec.failures++
	n := rec.failures
	if n >= lockoutFailureThreshold {
		rec.lockedUntil = now.Add(lockoutDuration)
	}

	return backoffDelay(n)
}

// Reset clears failure state after a successful login.
func (l *LockoutTracker) Reset(email string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.records, email)
	l.mu.Unlock()
}

func backoffDelay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	d := backoffBase
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= maxBackoff {
			return maxBackoff
		}
	}
	return d
}
