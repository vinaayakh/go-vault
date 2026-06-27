// Package storage is the injection-safe persistence layer. All queries use
// pgx parameterized placeholders ($1, $2, …) — no string concatenation, no
// fmt.Sprintf into SQL. See plan/phase-2-server-storage.md §2.2.
package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a record is not found (or not owned by the caller).
var ErrNotFound = errors.New("record not found")

// ErrConflict is returned when an optimistic-concurrency revision check fails.
// The client must fetch the latest revision before retrying the update.
var ErrConflict = errors.New("revision conflict: a newer version exists")

// Store holds the Postgres connection pool and the three repository implementations.
// It is safe for concurrent use; the pool manages connections internally.
type Store struct {
	pool     *pgxpool.Pool
	Users    *UsersRepo
	Items    *ItemsRepo
	Sessions *SessionsRepo
}

// New opens a connection pool and pings the database to verify connectivity.
// Returns an error (not a panic) so the caller can log and exit cleanly.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open pgxpool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	s := &Store{pool: pool}
	s.Users = &UsersRepo{pool: pool}
	s.Items = &ItemsRepo{pool: pool}
	s.Sessions = &SessionsRepo{pool: pool}
	return s, nil
}

// Ping checks that the database is reachable. Used by the /api/ready probe.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Close releases all connections in the pool. Call on graceful shutdown.
func (s *Store) Close() {
	s.pool.Close()
}
