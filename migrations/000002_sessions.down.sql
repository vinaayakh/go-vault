DROP INDEX IF EXISTS sessions_user_id_idx;
DROP INDEX IF EXISTS sessions_token_hash_idx;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS token_hash;
