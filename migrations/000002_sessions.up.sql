-- Phase 3: expand the stub sessions table with the full session schema.
-- token_hash stores SHA-256(raw_token) so a DB leak cannot be directly replayed.
-- expires_at enables server-side expiry checks without a background purge job.

ALTER TABLE sessions
    ADD COLUMN token_hash BYTEA        NOT NULL UNIQUE,
    ADD COLUMN expires_at TIMESTAMPTZ  NOT NULL;

CREATE INDEX sessions_token_hash_idx ON sessions (token_hash);
CREATE INDEX sessions_user_id_idx    ON sessions (user_id);
