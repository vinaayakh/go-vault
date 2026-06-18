package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// testParams is a deliberately cheap Argon2id cost so the suite runs fast. It is
// NOT the production default (DefaultKDFParams); correctness of the wiring does
// not depend on cost.
func testParams() KDFParams {
	return KDFParams{
		Type:        "argon2id",
		Version:     Argon2Version13,
		MemoryKiB:   8 * 1024, // 8 MiB
		Iterations:  1,
		Parallelism: 1,
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func TestDeriveMasterKey(t *testing.T) {
	t.Parallel()

	key, err := DeriveMasterKey([]byte("correct horse battery staple"), []byte("user@example.com"), testParams())
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	if len(key) != int(MasterKeySizeBytes) {
		t.Fatalf("master key size = %d, want %d", len(key), MasterKeySizeBytes)
	}
}

func TestDeriveMasterKeyDeterministic(t *testing.T) {
	t.Parallel()

	pw, salt := []byte("hunter2"), []byte("a@b.com")
	k1, err := DeriveMasterKey(pw, salt, testParams())
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveMasterKey(pw, salt, testParams())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("same inputs produced different master keys")
	}
}

func TestDeriveMasterKeyVariesByInput(t *testing.T) {
	t.Parallel()

	base, err := DeriveMasterKey([]byte("pw"), []byte("a@b.com"), testParams())
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		password, salt []byte
	}{
		"different password": {[]byte("pw2"), []byte("a@b.com")},
		"different salt":     {[]byte("pw"), []byte("c@d.com")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := DeriveMasterKey(tc.password, tc.salt, testParams())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, base) {
				t.Fatal("expected a different master key")
			}
		})
	}
}

func TestDeriveMasterKeyValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		password, salt []byte
		params         KDFParams
		wantErr        error
	}{
		"empty password":  {nil, []byte("salt"), testParams(), ErrEmptyPassword},
		"empty salt":      {[]byte("pw"), nil, testParams(), ErrEmptySalt},
		"zero memory":     {[]byte("pw"), []byte("salt"), KDFParams{Iterations: 1, Parallelism: 1}, nil},
		"zero iterations": {[]byte("pw"), []byte("salt"), KDFParams{MemoryKiB: 1024, Parallelism: 1}, nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := DeriveMasterKey(tc.password, tc.salt, tc.params)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.wantErr != nil && err != tc.wantErr {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestDeriveMasterKeyKAT pins the Argon2id output for fixed inputs/params. This
// is a regression known-answer test: it locks the wire format so any change to
// the library, params handling, or output size is caught. The vector was
// produced by golang.org/x/crypto/argon2.IDKey for the inputs below.
func TestDeriveMasterKeyKAT(t *testing.T) {
	t.Parallel()

	params := KDFParams{Type: "argon2id", Version: Argon2Version13, MemoryKiB: 64, Iterations: 1, Parallelism: 1}
	got, err := DeriveMasterKey([]byte("password"), []byte("somesalt"), params)
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, ARGON2_KAT)
	if !bytes.Equal(got, want) {
		t.Fatalf("Argon2id KAT mismatch:\n got  %x\n want %s", got, ARGON2_KAT)
	}
}

func TestStretchMasterKey(t *testing.T) {
	t.Parallel()

	mk := bytes.Repeat([]byte{0x42}, int(MasterKeySizeBytes))
	enc, mac, err := StretchMasterKey(mk)
	if err != nil {
		t.Fatalf("StretchMasterKey: %v", err)
	}
	if len(enc) != StretchedKeySizeBytes || len(mac) != StretchedKeySizeBytes {
		t.Fatalf("subkey sizes enc=%d mac=%d, want %d", len(enc), len(mac), StretchedKeySizeBytes)
	}
	if bytes.Equal(enc, mac) {
		t.Fatal("enc and mac keys must differ (distinct HKDF info labels)")
	}
}

func TestStretchMasterKeyDeterministic(t *testing.T) {
	t.Parallel()

	mk := bytes.Repeat([]byte{0x07}, int(MasterKeySizeBytes))
	enc1, mac1, err := StretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	enc2, mac2, err := StretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc1, enc2) || !bytes.Equal(mac1, mac2) {
		t.Fatal("HKDF output must be reproducible across calls")
	}
}

func TestStretchMasterKeyEmpty(t *testing.T) {
	t.Parallel()

	if _, _, err := StretchMasterKey(nil); err != ErrEmptyMasterKey {
		t.Fatalf("err = %v, want %v", err, ErrEmptyMasterKey)
	}
}
