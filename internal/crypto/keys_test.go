package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveAuthHash(t *testing.T) {
	t.Parallel()

	mk := bytes.Repeat([]byte{0x11}, int(MasterKeySizeBytes))
	hash, err := DeriveAuthHash(mk, []byte("master-password"), testParams())
	if err != nil {
		t.Fatalf("DeriveAuthHash: %v", err)
	}
	if len(hash) != int(AuthHashSizeBytes) {
		t.Fatalf("auth hash size = %d, want %d", len(hash), AuthHashSizeBytes)
	}
}

// TestAuthHashIndependentFromEncKey asserts the zero-knowledge invariant: the
// auth hash sent to the server must not equal (or trivially reveal) the HKDF
// encryption key. They are independent derivations from the same master key.
func TestAuthHashIndependentFromEncKey(t *testing.T) {
	t.Parallel()

	pw := []byte("correct horse battery staple")
	mk, err := DeriveMasterKey(pw, []byte("user@example.com"), testParams())
	if err != nil {
		t.Fatal(err)
	}
	enc, mac, err := StretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	authHash, err := DeriveAuthHash(mk, pw, testParams())
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(authHash, enc) {
		t.Fatal("auth hash equals the encryption key — server could decrypt the vault")
	}
	if bytes.Equal(authHash, mac) {
		t.Fatal("auth hash equals the mac key")
	}
	if bytes.Equal(authHash, mk) {
		t.Fatal("auth hash equals the master key")
	}
}

func TestDeriveAuthHashValidation(t *testing.T) {
	t.Parallel()

	mk := bytes.Repeat([]byte{0x11}, 32)
	tests := map[string]struct {
		masterKey, password []byte
		params              KDFParams
		wantErr             error
	}{
		"empty master key": {nil, []byte("pw"), testParams(), ErrEmptyMasterKey},
		"empty password":   {mk, nil, testParams(), ErrEmptyPassword},
		"bad params":       {mk, []byte("pw"), KDFParams{}, nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := DeriveAuthHash(tc.masterKey, tc.password, tc.params)
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.wantErr != nil && err != tc.wantErr {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDeriveServerAuthHash(t *testing.T) {
	t.Parallel()

	clientHash := bytes.Repeat([]byte{0x33}, int(AuthHashSizeBytes))
	salt, err := NewServerSalt()
	if err != nil {
		t.Fatal(err)
	}

	h1, err := DeriveServerAuthHash(clientHash, salt, DefaultServerAuthParams())
	if err != nil {
		t.Fatalf("DeriveServerAuthHash: %v", err)
	}
	if len(h1) != int(AuthHashSizeBytes) {
		t.Fatalf("server hash size = %d, want %d", len(h1), AuthHashSizeBytes)
	}

	// Same inputs reproduce; verification uses constant-time compare.
	h2, err := DeriveServerAuthHash(clientHash, salt, DefaultServerAuthParams())
	if err != nil {
		t.Fatal(err)
	}
	if !ConstantTimeEqual(h1, h2) {
		t.Fatal("server auth hash not reproducible for same salt+input")
	}

	// A different salt yields a different hash.
	salt2, err := NewServerSalt()
	if err != nil {
		t.Fatal(err)
	}
	h3, err := DeriveServerAuthHash(clientHash, salt2, DefaultServerAuthParams())
	if err != nil {
		t.Fatal(err)
	}
	if ConstantTimeEqual(h1, h3) {
		t.Fatal("different salts produced the same server auth hash")
	}
}

func TestDeriveServerAuthHashValidation(t *testing.T) {
	t.Parallel()

	if _, err := DeriveServerAuthHash(nil, []byte("salt"), DefaultServerAuthParams()); err != ErrEmptyAuthHash {
		t.Fatalf("err = %v, want %v", err, ErrEmptyAuthHash)
	}
	if _, err := DeriveServerAuthHash([]byte("h"), nil, DefaultServerAuthParams()); err != ErrEmptySalt {
		t.Fatalf("err = %v, want %v", err, ErrEmptySalt)
	}
}

func TestNewVaultKey(t *testing.T) {
	t.Parallel()

	k1, err := NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != VaultKeySizeBytes {
		t.Fatalf("vault key size = %d, want %d", len(k1), VaultKeySizeBytes)
	}

	k2, err := NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("two vault keys collided — randomness broken")
	}
	if bytes.Equal(k1, make([]byte, VaultKeySizeBytes)) {
		t.Fatal("vault key is all zeros")
	}
}

func TestNewServerSaltSize(t *testing.T) {
	t.Parallel()

	salt, err := NewServerSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(salt) != ServerSaltSizeBytes {
		t.Fatalf("salt size = %d, want %d", len(salt), ServerSaltSizeBytes)
	}
}

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in, want string
	}{
		"lowercases":           {"User@Example.COM", "user@example.com"},
		"trims whitespace":     {"  user@example.com  ", "user@example.com"},
		"trims and lowercases": {"\tUser@Example.com\n", "user@example.com"},
		"keeps plus address":   {"user+tag@example.com", "user+tag@example.com"},
		"keeps dots":           {"first.last@example.com", "first.last@example.com"},
		"already normalized":   {"user@example.com", "user@example.com"},
		"empty":                {"", ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeEmail(tc.in); got != tc.want {
				t.Fatalf("NormalizeEmail(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeEmailIdempotent guards the contract that client and server
// normalization agree: normalizing twice equals normalizing once.
func TestNormalizeEmailIdempotent(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"  USER@Example.com ", "a@b.com", "X+y.Z@D.com"} {
		once := NormalizeEmail(in)
		if twice := NormalizeEmail(once); once != twice {
			t.Fatalf("not idempotent for %q: %q != %q", in, once, twice)
		}
	}
}
