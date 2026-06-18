package crypto

import (
	"bytes"
	"testing"
)

func newTestKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	tests := map[string]struct {
		plaintext, aad []byte
	}{
		"simple":          {[]byte("hello world"), nil},
		"with aad":        {[]byte("secret"), []byte("item-id-123")},
		"empty plaintext": {[]byte{}, nil},
		"empty aad":       {[]byte("data"), []byte{}},
		"binary":          {bytes.Repeat([]byte{0x00, 0xff, 0x7f}, 100), []byte("ctx")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			blob, err := Seal(key, tc.plaintext, tc.aad)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			got, err := Open(key, blob, tc.aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, tc.plaintext) {
				t.Fatalf("round trip mismatch: got %q want %q", got, tc.plaintext)
			}
		})
	}
}

func TestSealProducesFreshNonce(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	pt := []byte("same plaintext")
	b1, err := Seal(key, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := Seal(key, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(b1, b2) {
		t.Fatal("two Seals of identical plaintext were equal — nonce reuse")
	}
	if bytes.Equal(b1[:NonceSizeBytes], b2[:NonceSizeBytes]) {
		t.Fatal("nonces were identical across Seals")
	}
}

func TestSealBlobLayout(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	pt := []byte("twelve bytes")
	blob, err := Seal(key, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	// nonce(24) + plaintext + tag(16)
	want := NonceSizeBytes + len(pt) + 16
	if len(blob) != want {
		t.Fatalf("blob length = %d, want %d", len(blob), want)
	}
}

// TestOpenKAT verifies Open against the published XChaCha20-Poly1305 vector from
// draft-irtf-cfrg-xchacha-03 §A.3.1, exercising the full nonce||ct||tag framing.
func TestOpenKAT(t *testing.T) {
	t.Parallel()

	key := mustHex(t, xchachaKey)
	blob := mustHex(t, xchachaBlob)
	aad := mustHex(t, xchachaAAD)
	wantPT := mustHex(t, xchachaPT)

	got, err := Open(key, blob, aad)
	if err != nil {
		t.Fatalf("Open(KAT): %v", err)
	}
	if !bytes.Equal(got, wantPT) {
		t.Fatalf("KAT mismatch:\n got  %x\n want %x", got, wantPT)
	}
}

func TestOpenTamperDetection(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	aad := []byte("ctx")
	blob, err := Seal(key, []byte("authentic data"), aad)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func([]byte) []byte{
		"flip nonce byte":      func(b []byte) []byte { c := clone(b); c[0] ^= 0x01; return c },
		"flip ciphertext byte": func(b []byte) []byte { c := clone(b); c[NonceSizeBytes] ^= 0x01; return c },
		"flip tag byte":        func(b []byte) []byte { c := clone(b); c[len(c)-1] ^= 0x01; return c },
		"truncate tag":         func(b []byte) []byte { return b[:len(b)-1] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Open(key, mutate(blob), aad); err != ErrOpen {
				t.Fatalf("err = %v, want %v", err, ErrOpen)
			}
		})
	}
}

func TestOpenWrongKey(t *testing.T) {
	t.Parallel()

	blob, err := Seal(newTestKey(t), []byte("data"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(newTestKey(t), blob, nil); err != ErrOpen {
		t.Fatalf("err = %v, want %v", err, ErrOpen)
	}
}

func TestOpenWrongAAD(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	blob, err := Seal(key, []byte("data"), []byte("aad-A"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, blob, []byte("aad-B")); err != ErrOpen {
		t.Fatalf("err = %v, want %v", err, ErrOpen)
	}
}

func TestOpenTooShort(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	if _, err := Open(key, make([]byte, NonceSizeBytes-1), nil); err != ErrCiphertextTooShort {
		t.Fatalf("err = %v, want %v", err, ErrCiphertextTooShort)
	}
}

func TestSealOpenInvalidKeySize(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := Seal(make([]byte, n), []byte("x"), nil); err != ErrInvalidKeySize {
			t.Fatalf("Seal key size %d: err = %v, want %v", n, err, ErrInvalidKeySize)
		}
		if _, err := Open(make([]byte, n), make([]byte, 64), nil); err != ErrInvalidKeySize {
			t.Fatalf("Open key size %d: err = %v, want %v", n, err, ErrInvalidKeySize)
		}
	}
}

func TestWrapUnwrapKey(t *testing.T) {
	t.Parallel()

	mk, err := DeriveMasterKey([]byte("pw"), []byte("a@b.com"), testParams())
	if err != nil {
		t.Fatal(err)
	}
	enc, _, err := StretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	vaultKey := newTestKey(t)

	protected, err := WrapKey(enc, vaultKey, nil)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if bytes.Contains(protected, vaultKey) {
		t.Fatal("protected key contains the raw vault key in cleartext")
	}

	got, err := UnwrapKey(enc, protected, nil)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(got, vaultKey) {
		t.Fatal("unwrapped key does not match original vault key")
	}
}

// TestMasterPasswordChange is the headline envelope-encryption invariant:
// changing the master password re-wraps the vault key but leaves every item
// ciphertext byte-for-byte unchanged.
func TestMasterPasswordChange(t *testing.T) {
	t.Parallel()

	email := []byte("user@example.com")
	vaultKey := newTestKey(t)

	// Encrypt some items under the (unchanging) vault key.
	items := []Item{
		{Name: "GitHub", Username: "octocat", Password: "s3cr3t", URL: "https://github.com"},
		{Name: "Email", Username: "me", Password: "hunter2", Notes: "personal"},
	}
	blobs := make([][]byte, len(items))
	blobsBefore := make([][]byte, len(items))
	for i, it := range items {
		b, err := EncryptItem(vaultKey, &it, nil)
		if err != nil {
			t.Fatal(err)
		}
		blobs[i] = b
		blobsBefore[i] = clone(b)
	}

	// Wrap the vault key under the OLD password.
	oldMK, err := DeriveMasterKey([]byte("old-password"), email, testParams())
	if err != nil {
		t.Fatal(err)
	}
	oldEnc, _, err := StretchMasterKey(oldMK)
	if err != nil {
		t.Fatal(err)
	}
	oldProtected, err := WrapKey(oldEnc, vaultKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	// --- Password change: unwrap with old, re-wrap with new. ---
	recovered, err := UnwrapKey(oldEnc, oldProtected, nil)
	if err != nil {
		t.Fatal(err)
	}
	newMK, err := DeriveMasterKey([]byte("new-password"), email, testParams())
	if err != nil {
		t.Fatal(err)
	}
	newEnc, _, err := StretchMasterKey(newMK)
	if err != nil {
		t.Fatal(err)
	}
	newProtected, err := WrapKey(newEnc, recovered, nil)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(oldProtected, newProtected) {
		t.Fatal("re-wrap produced identical protected key — wrapping not re-done")
	}

	// Item ciphertext must be byte-for-byte untouched by the password change,
	// and must still decrypt with the vault key recovered via the NEW path.
	for i, it := range items {
		if !bytes.Equal(blobs[i], blobsBefore[i]) {
			t.Fatalf("item %d ciphertext changed during password change", i)
		}
		got, err := DecryptItem(recovered, blobs[i], nil)
		if err != nil {
			t.Fatalf("decrypt after password change: %v", err)
		}
		if got != it {
			t.Fatalf("item %d changed after password change: got %+v want %+v", i, got, it)
		}
	}
}

func clone(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
