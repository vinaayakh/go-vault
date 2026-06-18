// Package crypto is the zero-knowledge crypto core: the master/vault key
// hierarchy, Argon2id KDF, AEAD (XChaCha20-Poly1305), and key wrapping. It is
// pure Go so the exact same implementation compiles to WASM for the browser
// (Phase 4) and is audited/fuzzed once, reused everywhere.
//
// Implemented in Phase 1 — see plan/phase-1-crypto-core.md.
package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// Argon2Version13 is the canonical Argon2 version constant (0x13 / 19).
	Argon2Version13 uint32 = argon2.Version
	// MasterKeySizeBytes is the required size for the derived master key.
	MasterKeySizeBytes uint32 = 32
	// StretchedKeySizeBytes is the size of each HKDF-derived subkey.
	StretchedKeySizeBytes = 32

	hkdfInfoEnc = "secure-vault:v1:enc"
	hkdfInfoMAC = "secure-vault:v1:mac"
)

var (
	ErrEmptyPassword  = errors.New("password must not be empty")
	ErrEmptySalt      = errors.New("salt must not be empty")
	ErrEmptyMasterKey = errors.New("master key must not be empty")
)

// KDFParams controls Argon2id derivation settings and is intended to be
// persisted with user/vault metadata so future parameter tuning is possible.
type KDFParams struct {
	Type        string `json:"type"`
	Version     uint32 `json:"version"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

// DefaultKDFParams returns the current Phase 1 Argon2id defaults.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Type:        "argon2id",
		Version:     Argon2Version13,
		MemoryKiB:   64 * 1024, // 64 MiB
		Iterations:  3,
		Parallelism: 1,
	}
}

// validate reports whether the Argon2id cost parameters are usable.
func (p KDFParams) validate() error {
	if p.MemoryKiB == 0 || p.Iterations == 0 || p.Parallelism == 0 {
		return errors.New("invalid KDF params: memory, iterations, and parallelism must be > 0")
	}
	return nil
}

// DeriveMasterKey derives a 32-byte master key from password + salt using
// Argon2id and the supplied parameters.
func DeriveMasterKey(password, salt []byte, params KDFParams) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	if len(salt) == 0 {
		return nil, ErrEmptySalt
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	masterKey := argon2.IDKey(
		password,
		salt,
		params.Iterations,
		params.MemoryKiB,
		params.Parallelism,
		MasterKeySizeBytes,
	)

	return masterKey, nil
}

// StretchMasterKey expands the master key into independent encryption and MAC
// keys using HKDF-SHA256 with fixed, versioned context labels.
func StretchMasterKey(masterKey []byte) (encKey, macKey []byte, err error) {
	if len(masterKey) == 0 {
		return nil, nil, ErrEmptyMasterKey
	}

	encKey, err = hkdfExpand(masterKey, hkdfInfoEnc, StretchedKeySizeBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("derive enc key: %w", err)
	}

	macKey, err = hkdfExpand(masterKey, hkdfInfoMAC, StretchedKeySizeBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("derive mac key: %w", err)
	}

	return encKey, macKey, nil
}

func hkdfExpand(secret []byte, info string, size int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, nil, []byte(info))
	out := make([]byte, size)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf expand failed: %w", err)
	}
	return out, nil
}
