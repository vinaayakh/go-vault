// Package storage is the injection-safe persistence layer: PostgreSQL access via
// sqlc-generated, fully parameterized queries behind Users and VaultItems
// repository interfaces. It stores only ciphertext + metadata at rest.
//
// Implemented in Phase 2 — see plan/phase-2-server-storage.md.
package storage
