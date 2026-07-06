DROP INDEX IF EXISTS sessions_refresh_token_hash_idx;
DROP INDEX IF EXISTS sessions_access_token_hash_idx;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS refresh_expires_at,
    DROP COLUMN IF EXISTS refresh_token_hash;

ALTER TABLE sessions RENAME COLUMN access_token_hash TO token_hash;
ALTER TABLE sessions RENAME COLUMN access_expires_at TO expires_at;

CREATE INDEX sessions_token_hash_idx ON sessions (token_hash);
