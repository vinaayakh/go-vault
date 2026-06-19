-- Phase 2 initial schema: users, vault_items, sessions (stub).
-- Zero-knowledge invariant: vault_items stores ONLY ciphertext + metadata.
-- The server never holds plaintext; auth_hash is derived server-side from
-- the client auth hash so the server cannot derive encryption keys.

CREATE TABLE users (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                    TEXT NOT NULL UNIQUE,
    -- kdf_params stores the Argon2id parameters so the client can re-derive
    -- the master key at login. JSON shape: {"type","version","memory_kib","iterations","parallelism"}
    kdf_params               JSONB NOT NULL,
    -- auth_hash = Argon2id(client_auth_hash, auth_hash_salt) — never the master password.
    -- The server compares this with constant-time equality at login.
    auth_hash                BYTEA NOT NULL,
    auth_hash_salt           BYTEA NOT NULL,
    -- protected_symmetric_key = AEAD_encrypt(vault_key, stretched_master_key).
    -- Returned at sync time so the client can unwrap the vault key.
    protected_symmetric_key  TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE vault_items (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- ciphertext = base64(nonce || AEAD(plaintext_item_json, vault_key)).
    -- Opaque to the server.
    ciphertext TEXT NOT NULL,
    item_type  TEXT NOT NULL CHECK (item_type IN ('login', 'note', 'card', 'identity')),
    -- revision is incremented by the server on every successful PUT.
    -- Clients supply their last-seen revision for optimistic concurrency (409 on conflict).
    revision   INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX vault_items_user_id_idx ON vault_items (user_id);

-- sessions is a Phase 3 stub. Table exists so foreign-key references compile.
CREATE TABLE sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
