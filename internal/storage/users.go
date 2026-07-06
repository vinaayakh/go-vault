package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vinaayakh/secure-vault/internal/storage/sqlcgen"
)

// User is the in-memory representation of a users row.
type User struct {
	ID                    uuid.UUID
	Email                 string
	KDFParams             json.RawMessage
	AuthHash              []byte
	AuthHashSalt          []byte
	ProtectedSymmetricKey string
	TOTPEnabled           bool
	ProtectedTOTPSecret   *string
	CreatedAt             time.Time
}

// UsersRepo provides injection-safe access to the users table via sqlc.
type UsersRepo struct {
	q *sqlcgen.Queries
}

// GetByID fetches a user row by UUID.
func (r *UsersRepo) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	u, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, mapNotFound(fmt.Errorf("get user by id: %w", err))
	}
	return userFromRow(&u), nil
}

// GetByEmail fetches a user row by normalized email.
func (r *UsersRepo) GetByEmail(ctx context.Context, email string) (*User, error) {
	u, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, mapNotFound(fmt.Errorf("get user by email: %w", err))
	}
	return userFromRow(&u), nil
}

// Create inserts a new user row.
func (r *UsersRepo) Create(
	ctx context.Context,
	email string,
	kdfParams json.RawMessage,
	authHash, authHashSalt []byte,
	protectedSymmetricKey string,
) (*User, error) {
	u, err := r.q.CreateUser(ctx, email, kdfParams, authHash, authHashSalt, protectedSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return userFromRow(&u), nil
}

// UpdateProtectedKey replaces the wrapped vault key.
func (r *UsersRepo) UpdateProtectedKey(ctx context.Context, id uuid.UUID, newKey string) (*User, error) {
	u, err := r.q.UpdateUserProtectedKey(ctx, id, newKey)
	if err != nil {
		return nil, mapNotFound(fmt.Errorf("update protected key: %w", err))
	}
	return userFromRow(&u), nil
}

// UpdateAuthCredentials atomically replaces auth material for master-password rotation.
func (r *UsersRepo) UpdateAuthCredentials(
	ctx context.Context,
	id uuid.UUID,
	newAuthHash, newAuthHashSalt []byte,
	newKDFParams json.RawMessage,
	newProtectedKey string,
) (*User, error) {
	u, err := r.q.UpdateUserAuthCredentials(ctx, sqlcgen.UpdateUserAuthCredentialsParams{
		ID:                    id,
		AuthHash:              newAuthHash,
		AuthHashSalt:          newAuthHashSalt,
		KdfParams:             newKDFParams,
		ProtectedSymmetricKey: newProtectedKey,
	})
	if err != nil {
		return nil, mapNotFound(fmt.Errorf("update auth credentials: %w", err))
	}
	return userFromRow(&u), nil
}

// DeleteUser removes the user row and cascaded children.
func (r *UsersRepo) DeleteUser(ctx context.Context, id uuid.UUID) error {
	n, err := r.q.DeleteUser(ctx, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
