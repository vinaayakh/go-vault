package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// User is the in-memory representation of a users row.
// auth_hash and auth_hash_salt are excluded from API responses — they are
// server-internal and never returned to clients.
type User struct {
	ID                    uuid.UUID
	Email                 string
	KDFParams             json.RawMessage
	AuthHash              []byte
	AuthHashSalt          []byte
	ProtectedSymmetricKey string
	CreatedAt             time.Time
}

// UsersRepo provides injection-safe access to the users table.
// All queries use pgx parameterized placeholders ($1, $2, …).
type UsersRepo struct {
	pool *pgxpool.Pool
}

const getUserByIDSQL = `
SELECT id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key, created_at
FROM users
WHERE id = $1
LIMIT 1`

// GetByID fetches a user row by UUID. Returns ErrNotFound when no row matches.
func (r *UsersRepo) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	u := &User{}
	err := r.pool.QueryRow(ctx, getUserByIDSQL, id).Scan(
		&u.ID, &u.Email, &u.KDFParams, &u.AuthHash, &u.AuthHashSalt,
		&u.ProtectedSymmetricKey, &u.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

const getUserByEmailSQL = `
SELECT id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key, created_at
FROM users
WHERE email = $1
LIMIT 1`

// GetByEmail fetches a user row by normalized email. Returns ErrNotFound when
// no row matches (callers must not reveal whether an email is registered).
func (r *UsersRepo) GetByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	err := r.pool.QueryRow(ctx, getUserByEmailSQL, email).Scan(
		&u.ID, &u.Email, &u.KDFParams, &u.AuthHash, &u.AuthHashSalt,
		&u.ProtectedSymmetricKey, &u.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

const createUserSQL = `
INSERT INTO users (email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key, created_at`

// Create inserts a new user row and returns the persisted record.
// email should be normalized via crypto.NormalizeEmail before calling.
func (r *UsersRepo) Create(
	ctx context.Context,
	email string,
	kdfParams json.RawMessage,
	authHash, authHashSalt []byte,
	protectedSymmetricKey string,
) (*User, error) {
	u := &User{}
	err := r.pool.QueryRow(ctx, createUserSQL,
		email, kdfParams, authHash, authHashSalt, protectedSymmetricKey,
	).Scan(
		&u.ID, &u.Email, &u.KDFParams, &u.AuthHash, &u.AuthHashSalt,
		&u.ProtectedSymmetricKey, &u.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

const updateProtectedKeySQL = `
UPDATE users
SET protected_symmetric_key = $2
WHERE id = $1
RETURNING id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key, created_at`

// UpdateProtectedKey replaces the wrapped vault key (e.g. after a master-password
// change in Phase 3+). Returns ErrNotFound when the user id does not exist.
func (r *UsersRepo) UpdateProtectedKey(ctx context.Context, id uuid.UUID, newKey string) (*User, error) {
	u := &User{}
	err := r.pool.QueryRow(ctx, updateProtectedKeySQL, id, newKey).Scan(
		&u.ID, &u.Email, &u.KDFParams, &u.AuthHash, &u.AuthHashSalt,
		&u.ProtectedSymmetricKey, &u.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update protected key: %w", err)
	}
	return u, nil
}

const updateAuthCredentialsSQL = //nolint:gosec // G101: SQL query constant, not a credential
`
UPDATE users
SET auth_hash               = $2,
    auth_hash_salt          = $3,
    kdf_params              = $4,
    protected_symmetric_key = $5
WHERE id = $1
RETURNING id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key, created_at`

// UpdateAuthCredentials atomically replaces auth material for a master-password
// rotation: new server-side auth hash, its salt, the updated KDF params, and the
// re-wrapped vault key. Returns ErrNotFound when the user id does not exist.
func (r *UsersRepo) UpdateAuthCredentials(
	ctx context.Context,
	id uuid.UUID,
	newAuthHash, newAuthHashSalt []byte,
	newKDFParams json.RawMessage,
	newProtectedKey string,
) (*User, error) {
	u := &User{}
	err := r.pool.QueryRow(ctx, updateAuthCredentialsSQL,
		id, newAuthHash, newAuthHashSalt, newKDFParams, newProtectedKey,
	).Scan(
		&u.ID, &u.Email, &u.KDFParams, &u.AuthHash, &u.AuthHashSalt,
		&u.ProtectedSymmetricKey, &u.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update auth credentials: %w", err)
	}
	return u, nil
}

const deleteUserSQL = `DELETE FROM users WHERE id = $1`

// DeleteUser removes the user row and all child rows (vault_items and sessions
// cascade via ON DELETE CASCADE). Returns ErrNotFound when the user does not exist.
func (r *UsersRepo) DeleteUser(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, deleteUserSQL, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
