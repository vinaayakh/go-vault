-- Phase 3+: dual-token sessions — short-lived access + rotating refresh tokens.
-- Both hashes are SHA-256(raw_token); raw tokens never stored.

ALTER TABLE sessions RENAME COLUMN token_hash TO access_token_hash;
ALTER TABLE sessions RENAME COLUMN expires_at TO access_expires_at;

ALTER TABLE sessions
    ADD COLUMN refresh_token_hash BYTEA        NOT NULL DEFAULT '\x00',
    ADD COLUMN refresh_expires_at TIMESTAMPTZ  NOT NULL DEFAULT NOW();

-- Backfill existing rows: derive refresh from access hash (one-time migration).
UPDATE sessions
SET refresh_token_hash = access_token_hash,
    refresh_expires_at = access_expires_at + INTERVAL '7 days'
WHERE refresh_token_hash = '\x00';

ALTER TABLE sessions ALTER COLUMN refresh_token_hash DROP DEFAULT;
ALTER TABLE sessions ALTER COLUMN refresh_expires_at DROP DEFAULT;

DROP INDEX IF EXISTS sessions_token_hash_idx;
CREATE UNIQUE INDEX sessions_access_token_hash_idx  ON sessions (access_token_hash);
CREATE UNIQUE INDEX sessions_refresh_token_hash_idx ON sessions (refresh_token_hash);
