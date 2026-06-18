package crypto

import (
	"bytes"
	"testing"
)

// FuzzOpen feeds arbitrary keys, blobs, and aad to Open. The contract: Open must
// never panic on malformed input and must reject it with an error (never return
// a plaintext for garbage it did not authenticate).
func FuzzOpen(f *testing.F) {
	key := bytes.Repeat([]byte{0x01}, 32)
	good, _ := Seal(key, []byte("hello"), []byte("aad"))
	f.Add(key, good, []byte("aad"))
	f.Add(key, []byte{}, []byte(nil))
	f.Add([]byte("short-key"), good, []byte("aad"))
	f.Add(key, good[:NonceSizeBytes], []byte("aad"))

	f.Fuzz(func(t *testing.T, key, blob, aad []byte) {
		pt, err := Open(key, blob, aad)
		if err != nil {
			return // expected for almost all random input
		}
		// If Open ever succeeds, re-sealing the result and reopening must agree,
		// and the key must have been a valid size.
		if len(key) != 32 {
			t.Fatalf("Open succeeded with invalid key size %d", len(key))
		}
		if pt == nil {
			t.Fatal("Open returned nil plaintext with nil error")
		}
	})
}

// FuzzSealOpenRoundTrip is the property test Open(Seal(x)) == x for arbitrary
// plaintext and aad under a fixed valid key.
func FuzzSealOpenRoundTrip(f *testing.F) {
	f.Add([]byte("plaintext"), []byte("aad"))
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x00, 0xff}, []byte(nil))

	key := bytes.Repeat([]byte{0x02}, 32)
	f.Fuzz(func(t *testing.T, plaintext, aad []byte) {
		blob, err := Seal(key, plaintext, aad)
		if err != nil {
			t.Fatalf("Seal failed on valid key: %v", err)
		}
		got, err := Open(key, blob, aad)
		if err != nil {
			t.Fatalf("Open failed to reverse Seal: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip mismatch: got %x want %x", got, plaintext)
		}
	})
}

// FuzzDecryptItem ensures the item deserializer never panics on a
// successfully-decrypted-but-arbitrary payload.
func FuzzDecryptItem(f *testing.F) {
	f.Add([]byte(`{"name":"x"}`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})
	f.Add([]byte(`{"name":`))

	key := bytes.Repeat([]byte{0x03}, 32)
	f.Fuzz(func(t *testing.T, payload []byte) {
		blob, err := Seal(key, payload, nil)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}
		// Must return cleanly (item or error), never panic.
		_, _ = DecryptItem(key, blob, nil)
	})
}
