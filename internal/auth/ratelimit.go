package auth

import (
	"sync"
	"time"
)

// RateLimiter is a thread-safe in-memory sliding-window rate limiter.
// It tracks request timestamps per key and prunes stale entries on each call.
type RateLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time
	limit   int
	window  time.Duration
}

func newRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		windows: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
	}
}

// Allow returns true if the key is under its rate limit and records the attempt.
// Returns false (and does NOT record) when the limit is already reached.
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.window)

	// Prune timestamps outside the current window.
	existing := r.windows[key]
	valid := existing[:0]
	for _, t := range existing {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= r.limit {
		r.windows[key] = valid
		return false
	}

	r.windows[key] = append(valid, now)
	return true
}

// Reset clears the rate-limit window for a key (e.g. after a successful login).
func (r *RateLimiter) Reset(key string) {
	r.mu.Lock()
	delete(r.windows, key)
	r.mu.Unlock()
}
