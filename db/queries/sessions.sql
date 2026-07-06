-- name: CreateSessionPair :one
INSERT INTO sessions (user_id, access_token_hash, access_expires_at, refresh_token_hash, refresh_expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, user_id, access_token_hash, access_expires_at, refresh_token_hash, refresh_expires_at, created_at;

-- name: GetSessionByAccessHash :one
SELECT id, user_id, access_token_hash, access_expires_at, refresh_token_hash, refresh_expires_at, created_at
FROM sessions
WHERE access_token_hash = $1
LIMIT 1;

-- name: GetSessionByRefreshHash :one
SELECT id, user_id, access_token_hash, access_expires_at, refresh_token_hash, refresh_expires_at, created_at
FROM sessions
WHERE refresh_token_hash = $1
LIMIT 1;

-- name: RotateSessionTokens :one
UPDATE sessions
SET access_token_hash  = $2,
    access_expires_at  = $3,
    refresh_token_hash = $4,
    refresh_expires_at = $5
WHERE id = $1
RETURNING id, user_id, access_token_hash, access_expires_at, refresh_token_hash, refresh_expires_at, created_at;

-- name: DeleteSessionByAccessHash :exec
DELETE FROM sessions WHERE access_token_hash = $1;

-- name: DeleteSessionByRefreshHash :exec
DELETE FROM sessions WHERE refresh_token_hash = $1;

-- name: DeleteAllSessionsForUser :exec
DELETE FROM sessions WHERE user_id = $1;
