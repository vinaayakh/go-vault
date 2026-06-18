package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// VaultKeySizeBytes is the size of a randomly generated vault key.
	VaultKeySizeBytes = 32
	// AuthHashSizeBytes is the size of the client and server auth hashes.
	AuthHashSizeBytes uint32 = 32
	// ServerSaltSizeBytes is the per-user random salt size for the server-side
	// auth-hash pass (NOT the email).
	ServerSaltSizeBytes = 16
)

// ErrEmptyAuthHash is returned when the client auth hash input is empty.
var ErrEmptyAuthHash = errors.New("auth hash input must not be empty")

// DefaultServerAuthParams returns the Argon2id parameters for the server-side
// (third) auth-hash pass. Its input is already a 32-byte high-entropy value, so
// this pass defends only the at-rest hash, not a low-entropy password — hence
// the lighter OWASP-minimum cost (m=19 MiB, t=2, p=1). See plan/phase-3-auth.md.
func DefaultServerAuthParams() KDFParams {
	return KDFParams{
		Type:        "argon2id",
		Version:     Argon2Version13,
		MemoryKiB:   19 * 1024, // 19 MiB
		Iterations:  2,
		Parallelism: 1,
	}
}

// DeriveAuthHash derives the client auth hash sent to the server. It is a
// SECOND, independent Argon2id pass over the master key, salted with the master
// password. Because it is derived separately from the HKDF encryption keys, the
// server learns nothing that can decrypt the vault (zero-knowledge invariant).
func DeriveAuthHash(masterKey, password []byte, params KDFParams) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, ErrEmptyMasterKey
	}
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	return argon2.IDKey(
		masterKey,
		password,
		params.Iterations,
		params.MemoryKiB,
		params.Parallelism,
		AuthHashSizeBytes,
	), nil
}

// DeriveServerAuthHash performs the third Argon2id pass the server stores at
// rest: Argon2id(clientAuthHash, salt). The salt must be a per-user random value
// from NewServerSalt (never the email). The result is compared against the
// stored hash with ConstantTimeEqual at login.
func DeriveServerAuthHash(clientAuthHash, salt []byte, params KDFParams) ([]byte, error) {
	if len(clientAuthHash) == 0 {
		return nil, ErrEmptyAuthHash
	}
	if len(salt) == 0 {
		return nil, ErrEmptySalt
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	return argon2.IDKey(
		clientAuthHash,
		salt,
		params.Iterations,
		params.MemoryKiB,
		params.Parallelism,
		AuthHashSizeBytes,
	), nil
}

// NewVaultKey returns a fresh 32-byte vault key from crypto/rand (the CSPRNG).
// Never use math/rand for key material.
func NewVaultKey() ([]byte, error) {
	return randomBytes(VaultKeySizeBytes)
}

// NewServerSalt returns a fresh 16-byte per-user salt for the server-side
// auth-hash pass, from crypto/rand.
func NewServerSalt() ([]byte, error) {
	return randomBytes(ServerSaltSizeBytes)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return b, nil
}

// NormalizeEmail canonicalizes an email for use as the KDF salt and for
// server-side lookup. It trims surrounding whitespace and lowercases the whole
// address. It deliberately does NOT apply plus-address or dot stripping — those
// change the user's real identity. The SAME function must run client- and
// server-side so derived keys and lookups agree.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
