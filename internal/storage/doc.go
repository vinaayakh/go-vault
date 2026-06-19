// Package storage is the injection-safe persistence layer: PostgreSQL access via
// fully parameterized pgx queries behind UsersRepo and ItemsRepo.
// It stores only ciphertext + metadata at rest — the zero-knowledge invariant.
//
// See plan/phase-2-server-storage.md for design decisions (full-snapshot sync,
// optimistic concurrency via revision, least-privilege app role, etc.).
package storage
