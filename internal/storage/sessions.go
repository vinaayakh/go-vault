package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vinaayakh/secure-vault/internal/storage/sqlcgen"
)

// Session is the in-memory representation of a sessions row.
type Session struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	AccessTokenHash  []byte
	AccessExpiresAt  time.Time
	RefreshTokenHash []byte
	RefreshExpiresAt time.Time
	CreatedAt        time.Time
}

// SessionsRepo provides parameterized access to the sessions table via sqlc.
type SessionsRepo struct {
	q *sqlcgen.Queries
}

// CreatePair inserts a new session with access and refresh token hashes.
func (r *SessionsRepo) CreatePair(
	ctx context.Context,
	userID uuid.UUID,
	accessHash []byte,
	accessExpiresAt time.Time,
	refreshHash []byte,
	refreshExpiresAt time.Time,
) (*Session, error) {
	s, err := r.q.CreateSessionPair(ctx, sqlcgen.CreateSessionPairParams{
		UserID:           userID,
		AccessTokenHash:  accessHash,
		AccessExpiresAt:  accessExpiresAt,
		RefreshTokenHash: refreshHash,
		RefreshExpiresAt: refreshExpiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("create session pair: %w", err)
	}
	return sessionFromRow(&s), nil
}

// GetByAccessHash looks up a session by access token hash.
func (r *SessionsRepo) GetByAccessHash(ctx context.Context, accessHash []byte) (*Session, error) {
	s, err := r.q.GetSessionByAccessHash(ctx, accessHash)
	if err != nil {
		return nil, mapNotFound(fmt.Errorf("get session by access hash: %w", err))
	}
	return sessionFromRow(&s), nil
}

// GetByRefreshHash looks up a session by refresh token hash.
func (r *SessionsRepo) GetByRefreshHash(ctx context.Context, refreshHash []byte) (*Session, error) {
	s, err := r.q.GetSessionByRefreshHash(ctx, refreshHash)
	if err != nil {
		return nil, mapNotFound(fmt.Errorf("get session by refresh hash: %w", err))
	}
	return sessionFromRow(&s), nil
}

// RotateTokens replaces access and refresh hashes for an existing session row.
func (r *SessionsRepo) RotateTokens(
	ctx context.Context,
	sessionID uuid.UUID,
	accessHash []byte,
	accessExpiresAt time.Time,
	refreshHash []byte,
	refreshExpiresAt time.Time,
) (*Session, error) {
	s, err := r.q.RotateSessionTokens(ctx, sqlcgen.RotateSessionTokensParams{
		ID:               sessionID,
		AccessTokenHash:  accessHash,
		AccessExpiresAt:  accessExpiresAt,
		RefreshTokenHash: refreshHash,
		RefreshExpiresAt: refreshExpiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("rotate session tokens: %w", err)
	}
	return sessionFromRow(&s), nil
}

// DeleteByAccessHash removes a session by access token hash.
func (r *SessionsRepo) DeleteByAccessHash(ctx context.Context, accessHash []byte) error {
	if err := r.q.DeleteSessionByAccessHash(ctx, accessHash); err != nil {
		return fmt.Errorf("delete session by access hash: %w", err)
	}
	return nil
}

// DeleteByRefreshHash removes a session by refresh token hash.
func (r *SessionsRepo) DeleteByRefreshHash(ctx context.Context, refreshHash []byte) error {
	if err := r.q.DeleteSessionByRefreshHash(ctx, refreshHash); err != nil {
		return fmt.Errorf("delete session by refresh hash: %w", err)
	}
	return nil
}

// DeleteAllForUser removes every session belonging to the given user.
func (r *SessionsRepo) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	if err := r.q.DeleteAllSessionsForUser(ctx, userID); err != nil {
		return fmt.Errorf("delete all sessions for user: %w", err)
	}
	return nil
}
