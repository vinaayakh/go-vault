package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// NonceSizeBytes is the XChaCha20-Poly1305 nonce length (192-bit). A 24-byte
// nonce is large enough that random nonces are safe for long-lived keys without
// a counter.
const NonceSizeBytes = chacha20poly1305.NonceSizeX

var (
	// ErrInvalidKeySize is returned when an AEAD key is not 32 bytes.
	ErrInvalidKeySize = errors.New("key must be 32 bytes")
	// ErrCiphertextTooShort is returned when a blob is shorter than the nonce.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	// ErrOpen is returned when authentication/decryption fails. It is
	// deliberately opaque: callers must not learn whether the key, nonce, or tag
	// was at fault.
	ErrOpen = errors.New("decryption failed: authentication error")
)

// Seal encrypts plaintext with XChaCha20-Poly1305 under key, binding aad into
// the authentication tag. A fresh random 24-byte nonce is generated per call and
// prepended to the output. The blob layout is:
//
//	nonce(24) || ciphertext || tag(16)
//
// aad (which may be nil) is authenticated but not encrypted; use it to bind the
// ciphertext to its context (e.g. an item id).
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends the ciphertext+tag to nonce, yielding nonce || ct || tag.
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open splits the leading nonce from blob, then authenticates and decrypts the
// remainder with the same aad supplied to Seal. Any failure (wrong key, tampered
// ciphertext, mismatched aad, truncated blob) returns ErrOpen with no detail.
func Open(key, blob, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	if len(blob) < aead.NonceSize() {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}

// WrapKey encrypts a vault key under the stretched master encryption key,
// producing the protected symmetric key stored on the server. It is Seal with
// key-material semantics; aad may bind the wrapped key to its owner.
func WrapKey(wrappingKey, vaultKey, aad []byte) ([]byte, error) {
	return Seal(wrappingKey, vaultKey, aad)
}

// UnwrapKey reverses WrapKey, recovering the raw vault key. The caller is
// responsible for zeroing the returned key after use (see Zero).
func UnwrapKey(wrappingKey, protectedKey, aad []byte) ([]byte, error) {
	return Open(wrappingKey, protectedKey, aad)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKeySize
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		// Unreachable given the length check above, but never panic on key input.
		return nil, ErrInvalidKeySize
	}
	return aead, nil
}
