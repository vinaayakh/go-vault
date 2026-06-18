package crypto

import (
	"bytes"
	"testing"
)

func TestZero(t *testing.T) {
	t.Parallel()

	b := []byte{1, 2, 3, 4, 5}
	Zero(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatalf("Zero left non-zero bytes: %v", b)
	}
}

func TestZeroEmpty(t *testing.T) {
	t.Parallel()

	Zero(nil)      // must not panic
	Zero([]byte{}) // must not panic
}

func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		a, b []byte
		want bool
	}{
		"equal":            {[]byte("secret"), []byte("secret"), true},
		"different":        {[]byte("secret"), []byte("sekret"), false},
		"different length": {[]byte("short"), []byte("longer"), false},
		"both empty":       {[]byte{}, []byte{}, true},
		"one empty":        {[]byte{}, []byte("x"), false},
		"nil equal":        {nil, nil, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := ConstantTimeEqual(tc.a, tc.b); got != tc.want {
				t.Fatalf("ConstantTimeEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
