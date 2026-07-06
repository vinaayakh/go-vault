-- name: DeleteRecoveryCodesForUser :exec
DELETE FROM recovery_codes WHERE user_id = $1;

-- name: InsertRecoveryCode :exec
INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2);

-- name: ListUnusedRecoveryCodes :many
SELECT id, code_hash FROM recovery_codes
WHERE user_id = $1 AND used_at IS NULL;

-- name: MarkRecoveryCodeUsed :execrows
UPDATE recovery_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL;

-- name: CreateMFAChallenge :exec
INSERT INTO mfa_challenges (user_id, token_hash, expires_at)
VALUES ($1, $2, $3);

-- name: ConsumeMFAChallenge :one
DELETE FROM mfa_challenges
WHERE token_hash = $1 AND expires_at > NOW()
RETURNING user_id;

-- name: CleanupExpiredMFAChallenges :exec
DELETE FROM mfa_challenges WHERE expires_at <= NOW();
