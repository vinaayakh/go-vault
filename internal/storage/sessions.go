package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Session is the in-memory representation of a sessions row.
// TokenHash is SHA-256 of the raw session token; the raw token is never stored.
type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// SessionsRepo provides parameterized access to the sessions table.
type SessionsRepo struct {
	pool *pgxpool.Pool
}

const createSessionSQL = `
INSERT INTO sessions (user_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING id, user_id, token_hash, expires_at, created_at`

// Create inserts a new session row and returns the persisted record.
func (r *SessionsRepo) Create(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) (*Session, error) {
	s := &Session{}
	err := r.pool.QueryRow(ctx, createSessionSQL, userID, tokenHash, expiresAt).Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.ExpiresAt, &s.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return s, nil
}

const getSessionByTokenHashSQL = //nolint:gosec // G101: SQL query constant, not a credential
`
SELECT id, user_id, token_hash, expires_at, created_at
FROM sessions
WHERE token_hash = $1
LIMIT 1`

// GetByTokenHash looks up a session by the SHA-256 hash of the raw token.
// Returns ErrNotFound when no matching row exists.
func (r *SessionsRepo) GetByTokenHash(ctx context.Context, tokenHash []byte) (*Session, error) {
	s := &Session{}
	err := r.pool.QueryRow(ctx, getSessionByTokenHashSQL, tokenHash).Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.ExpiresAt, &s.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get session by token hash: %w", err)
	}
	return s, nil
}

const deleteSessionSQL = `DELETE FROM sessions WHERE token_hash = $1`

// Delete removes a single session by token hash (logout).
func (r *SessionsRepo) Delete(ctx context.Context, tokenHash []byte) error {
	_, err := r.pool.Exec(ctx, deleteSessionSQL, tokenHash)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

const deleteAllSessionsForUserSQL = `DELETE FROM sessions WHERE user_id = $1`

// DeleteAllForUser removes every session belonging to the given user (account
// deletion or "sign out everywhere").
func (r *SessionsRepo) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, deleteAllSessionsForUserSQL, userID)
	if err != nil {
		return fmt.Errorf("delete all sessions for user: %w", err)
	}
	return nil
}
