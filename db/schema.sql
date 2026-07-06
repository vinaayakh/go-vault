-- Consolidated schema for sqlc code generation (final state after all migrations).
-- Runtime migrations live in migrations/; keep this file in sync when schema changes.

CREATE TABLE users (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                    TEXT NOT NULL UNIQUE,
    kdf_params               JSONB NOT NULL,
    auth_hash                BYTEA NOT NULL,
    auth_hash_salt           BYTEA NOT NULL,
    protected_symmetric_key  TEXT NOT NULL,
    totp_enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    protected_totp_secret    TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE vault_items (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,
    item_type  TEXT NOT NULL CHECK (item_type IN ('login', 'note', 'card', 'identity')),
    revision   INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX vault_items_user_id_idx ON vault_items (user_id);

CREATE TABLE sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token_hash  BYTEA NOT NULL UNIQUE,
    access_expires_at  TIMESTAMPTZ NOT NULL,
    refresh_token_hash BYTEA NOT NULL UNIQUE,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE TABLE recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  BYTEA NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX recovery_codes_user_id_idx ON recovery_codes(user_id);

CREATE TABLE mfa_challenges (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX mfa_challenges_expires_idx ON mfa_challenges(expires_at);

CREATE TABLE audit_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type  TEXT NOT NULL,
    ip          INET,
    user_agent  TEXT,
    resource_id UUID,
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_events_user_created_idx ON audit_events(user_id, created_at DESC);

CREATE TABLE user_device_hashes (
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ua_hash       BYTEA NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, ua_hash)
);
