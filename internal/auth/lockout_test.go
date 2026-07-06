package auth

import (
	"testing"
)

func TestLockoutTracker_LocksAfterThreshold(t *testing.T) {
	l := newLockoutTracker()
	email := "user@example.com"

	for i := 0; i < lockoutFailureThreshold-1; i++ {
		if l.IsLocked(email) {
			t.Fatalf("should not be locked after %d failures", i+1)
		}
		l.RecordFailure(email)
	}

	l.RecordFailure(email)
	if !l.IsLocked(email) {
		t.Fatal("should be locked after threshold failures")
	}
}

func TestLockoutTracker_ResetClearsLock(t *testing.T) {
	l := newLockoutTracker()
	email := "user@example.com"
	for i := 0; i < lockoutFailureThreshold; i++ {
		l.RecordFailure(email)
	}
	l.Reset(email)
	if l.IsLocked(email) {
		t.Fatal("reset should clear lockout")
	}
}

func TestBackoffDelay_Capped(t *testing.T) {
	d := backoffDelay(100)
	if d != maxBackoff {
		t.Fatalf("expected max backoff %v, got %v", maxBackoff, d)
	}
}

func TestBackoffDelay_Grows(t *testing.T) {
	d1 := backoffDelay(1)
	d2 := backoffDelay(3)
	if d2 <= d1 {
		t.Fatalf("backoff should grow: %v vs %v", d1, d2)
	}
}
