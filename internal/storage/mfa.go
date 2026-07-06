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

// MFARepo manages TOTP enrollment, recovery codes, and login challenges.
type MFARepo struct {
	pool *pgxpool.Pool
}

const enableTOTPSQL = `
UPDATE users
SET totp_enabled = TRUE, protected_totp_secret = $2
WHERE id = $1`

// EnableTOTP stores the wrapped secret and enables 2FA.
func (r *MFARepo) EnableTOTP(ctx context.Context, userID uuid.UUID, protectedSecret string) error {
	tag, err := r.pool.Exec(ctx, enableTOTPSQL, userID, protectedSecret)
	if err != nil {
		return fmt.Errorf("enable totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const disableTOTPSQL = `
UPDATE users
SET totp_enabled = FALSE, protected_totp_secret = NULL
WHERE id = $1`

// DisableTOTP turns off 2FA and clears the stored secret.
func (r *MFARepo) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, disableTOTPSQL, userID)
	if err != nil {
		return fmt.Errorf("disable totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, _ = r.pool.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID)
	return nil
}

const getTOTPStatusSQL = `
SELECT totp_enabled, protected_totp_secret FROM users WHERE id = $1`

// GetTOTPStatus returns whether 2FA is enabled and the wrapped secret.
func (r *MFARepo) GetTOTPStatus(ctx context.Context, userID uuid.UUID) (enabled bool, protectedSecret *string, err error) {
	var secret *string
	err = r.pool.QueryRow(ctx, getTOTPStatusSQL, userID).Scan(&enabled, &secret)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, ErrNotFound
	}
	if err != nil {
		return false, nil, fmt.Errorf("get totp status: %w", err)
	}
	return enabled, secret, nil
}

const insertRecoveryCodeSQL = `
INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`

// ReplaceRecoveryCodes deletes existing codes and inserts new hashed codes.
func (r *MFARepo) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, hashes [][]byte) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, insertRecoveryCodeSQL, userID, h); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return tx.Commit(ctx)
}

const findUnusedRecoverySQL = `
SELECT id, code_hash FROM recovery_codes
WHERE user_id = $1 AND used_at IS NULL`

// ConsumeRecoveryCode marks a matching unused code as used. Returns true if found.
func (r *MFARepo) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, match func(hash []byte) bool) (bool, error) {
	rows, err := r.pool.Query(ctx, findUnusedRecoverySQL, userID)
	if err != nil {
		return false, fmt.Errorf("list recovery codes: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id uuid.UUID
		var hash []byte
		if err := rows.Scan(&id, &hash); err != nil {
			return false, err
		}
		if match(hash) {
			tag, err := r.pool.Exec(ctx,
				`UPDATE recovery_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, id)
			if err != nil {
				return false, err
			}
			return tag.RowsAffected() > 0, nil
		}
	}
	return false, rows.Err()
}

const createChallengeSQL = `
INSERT INTO mfa_challenges (user_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING id`

// CreateChallenge stores a hashed MFA challenge token.
func (r *MFARepo) CreateChallenge(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, createChallengeSQL, userID, tokenHash, expiresAt)
	return err
}

const consumeChallengeSQL = `
DELETE FROM mfa_challenges
WHERE token_hash = $1 AND expires_at > NOW()
RETURNING user_id`

// ConsumeChallenge validates and deletes a challenge token. Returns user ID.
func (r *MFARepo) ConsumeChallenge(ctx context.Context, tokenHash []byte) (uuid.UUID, error) {
	var userID uuid.UUID
	err := r.pool.QueryRow(ctx, consumeChallengeSQL, tokenHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("consume mfa challenge: %w", err)
	}
	return userID, nil
}

// CleanupExpiredChallenges removes stale MFA challenges (best-effort).
func (r *MFARepo) CleanupExpiredChallenges(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM mfa_challenges WHERE expires_at <= NOW()`)
	return err
}
