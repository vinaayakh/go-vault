package auth

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.Allow("key") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_BlocksAtLimit(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.Allow("key")
	}
	if rl.Allow("key") {
		t.Fatal("fourth attempt should be blocked")
	}
}

func TestRateLimiter_IndependentKeys(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)
	rl.Allow("a")
	if !rl.Allow("b") {
		t.Fatal("key 'b' should not be affected by key 'a' limit")
	}
}

func TestRateLimiter_ResetClearsWindow(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)
	rl.Allow("key")
	rl.Allow("key")
	rl.Reset("key")
	if !rl.Allow("key") {
		t.Fatal("after Reset, first attempt should be allowed again")
	}
}

func TestRateLimiter_SlidingWindowExpiry(t *testing.T) {
	rl := newRateLimiter(2, 100*time.Millisecond)
	rl.Allow("key")
	rl.Allow("key")
	// Wait for the window to expire.
	time.Sleep(150 * time.Millisecond)
	if !rl.Allow("key") {
		t.Fatal("attempt after window expiry should be allowed")
	}
}
