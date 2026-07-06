// Package storage is the injection-safe persistence layer backed by sqlc-generated
// queries in sqlcgen/. See docs/THREAT_MODEL.md for design decisions.
package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vinaayakh/secure-vault/internal/storage/sqlcgen"
)

// ErrNotFound is returned when a record is not found (or not owned by the caller).
var ErrNotFound = errors.New("record not found")

// ErrConflict is returned when an optimistic-concurrency revision check fails.
var ErrConflict = errors.New("revision conflict: a newer version exists")

// Store holds the Postgres connection pool and repository implementations.
type Store struct {
	pool     *pgxpool.Pool
	q        *sqlcgen.Queries
	Users    *UsersRepo
	Items    *ItemsRepo
	Sessions *SessionsRepo
	Audit    *AuditRepo
	MFA      *MFARepo
}

// New opens a connection pool and pings the database to verify connectivity.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open pgxpool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	q := sqlcgen.New(pool)
	s := &Store{pool: pool, q: q}
	s.Users = &UsersRepo{q: q}
	s.Items = &ItemsRepo{q: q}
	s.Sessions = &SessionsRepo{q: q}
	s.Audit = &AuditRepo{q: q}
	s.MFA = &MFARepo{q: q, pool: pool}
	return s, nil
}

// Ping checks that the database is reachable. Used by the /api/ready probe.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Close releases all connections in the pool.
func (s *Store) Close() {
	s.pool.Close()
}

func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
