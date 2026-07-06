package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vinaayakh/secure-vault/internal/storage/sqlcgen"
)

// MFARepo manages TOTP enrollment, recovery codes, and login challenges via sqlc.
type MFARepo struct {
	q    *sqlcgen.Queries
	pool *pgxpool.Pool
}

// EnableTOTP stores the wrapped secret and enables 2FA.
func (r *MFARepo) EnableTOTP(ctx context.Context, userID uuid.UUID, protectedSecret string) error {
	n, err := r.q.EnableUserTOTP(ctx, userID, &protectedSecret)
	if err != nil {
		return fmt.Errorf("enable totp: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DisableTOTP turns off 2FA and clears recovery codes.
func (r *MFARepo) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	n, err := r.q.DisableUserTOTP(ctx, userID)
	if err != nil {
		return fmt.Errorf("disable totp: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return r.q.DeleteRecoveryCodesForUser(ctx, userID)
}

// GetTOTPStatus returns whether 2FA is enabled and the wrapped secret.
func (r *MFARepo) GetTOTPStatus(ctx context.Context, userID uuid.UUID) (enabled bool, protectedSecret *string, err error) {
	row, err := r.q.GetUserTOTPStatus(ctx, userID)
	if mapNotFound(err) == ErrNotFound {
		return false, nil, ErrNotFound
	}
	if err != nil {
		return false, nil, fmt.Errorf("get totp status: %w", err)
	}
	return row.TotpEnabled, row.ProtectedTotpSecret, nil
}

// ReplaceRecoveryCodes deletes existing codes and inserts new hashed codes.
func (r *MFARepo) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, hashes [][]byte) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	qtx := r.q.WithTx(tx)
	if err := qtx.DeleteRecoveryCodesForUser(ctx, userID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	for _, h := range hashes {
		if err := qtx.InsertRecoveryCode(ctx, userID, h); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// ConsumeRecoveryCode marks a matching unused code as used.
func (r *MFARepo) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, match func(hash []byte) bool) (bool, error) {
	codes, err := r.q.ListUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("list recovery codes: %w", err)
	}
	for _, c := range codes {
		if match(c.CodeHash) {
			n, err := r.q.MarkRecoveryCodeUsed(ctx, c.ID)
			if err != nil {
				return false, err
			}
			return n > 0, nil
		}
	}
	return false, nil
}

// CreateChallenge stores a hashed MFA challenge token.
func (r *MFARepo) CreateChallenge(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	return r.q.CreateMFAChallenge(ctx, userID, tokenHash, expiresAt)
}

// ConsumeChallenge validates and deletes a challenge token.
func (r *MFARepo) ConsumeChallenge(ctx context.Context, tokenHash []byte) (uuid.UUID, error) {
	userID, err := r.q.ConsumeMFAChallenge(ctx, tokenHash)
	if mapNotFound(err) == ErrNotFound {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("consume mfa challenge: %w", err)
	}
	return userID, nil
}

// CleanupExpiredChallenges removes stale MFA challenges.
func (r *MFARepo) CleanupExpiredChallenges(ctx context.Context) error {
	return r.q.CleanupExpiredMFAChallenges(ctx)
}

// compile-time check pgx used in WithTx
var _ = pgx.Tx(nil)
