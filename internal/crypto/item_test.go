package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptItem(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	item := Item{
		Name:     "GitHub",
		Username: "octocat",
		Password: "correct horse battery staple",
		URL:      "https://github.com",
		Notes:    "work account\nsecond line",
		TOTPSeed: "JBSWY3DPEHPK3PXP",
	}

	blob, err := EncryptItem(key, &item, []byte("item-42"))
	if err != nil {
		t.Fatalf("EncryptItem: %v", err)
	}

	// The ciphertext must not leak any plaintext field.
	for _, secret := range []string{item.Password, item.TOTPSeed, item.Username, item.Notes} {
		if bytes.Contains(blob, []byte(secret)) {
			t.Fatalf("ciphertext leaked plaintext field %q", secret)
		}
	}

	got, err := DecryptItem(key, blob, []byte("item-42"))
	if err != nil {
		t.Fatalf("DecryptItem: %v", err)
	}
	if got != item {
		t.Fatalf("round trip mismatch:\n got  %+v\n want %+v", got, item)
	}
}

func TestEncryptDecryptItemEmpty(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	item := Item{}
	blob, err := EncryptItem(key, &item, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptItem(key, blob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != (Item{}) {
		t.Fatalf("empty item round trip = %+v", got)
	}
}

func TestDecryptItemWrongAAD(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	item := Item{Name: "x"}
	blob, err := EncryptItem(key, &item, []byte("id-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptItem(key, blob, []byte("id-2")); err != ErrOpen {
		t.Fatalf("err = %v, want %v", err, ErrOpen)
	}
}

func TestDecryptItemTampered(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	item := Item{Name: "x", Password: "y"}
	blob, err := EncryptItem(key, &item, nil)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0x01
	if _, err := DecryptItem(key, blob, nil); err != ErrOpen {
		t.Fatalf("err = %v, want %v", err, ErrOpen)
	}
}

// TestDecryptItemMalformedJSON forces a successfully-decrypted-but-non-JSON
// payload to confirm DecryptItem surfaces an unmarshal error rather than
// panicking. We seal raw non-JSON bytes under the same key.
func TestDecryptItemMalformedJSON(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	blob, err := Seal(key, []byte("this is not json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptItem(key, blob, nil); err == nil {
		t.Fatal("expected unmarshal error for non-JSON plaintext")
	}
}
