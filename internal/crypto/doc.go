// Package crypto is the zero-knowledge crypto core: the master/vault key
// hierarchy, Argon2id KDF, AEAD (XChaCha20-Poly1305), and key wrapping. It is
// pure Go so the exact same implementation compiles to WASM for the browser
// (Phase 4) and is audited/fuzzed once, reused everywhere.
//
// Implemented in Phase 1 — see plan/phase-1-crypto-core.md.
package crypto
