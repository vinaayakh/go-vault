# Secure Vault export format (v1)

Encrypted vault exports are **client-side JSON files** containing only ciphertext and
metadata — the same material already stored on the server.

## File structure

```json
{
  "format": "secure-vault-export",
  "version": 1,
  "exported_at": "2026-07-06T12:00:00.000Z",
  "email": "user@example.com",
  "kdf_params": {
    "type": "argon2id",
    "version": 19,
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1
  },
  "protected_symmetric_key": "<base64 wrapped vault key>",
  "totp_enabled": false,
  "protected_totp_secret": "<optional, vault-key-wrapped TOTP secret>",
  "items": [
    {
      "id": "uuid",
      "item_type": "login",
      "ciphertext": "<base64 AEAD blob>",
      "revision": 1,
      "updated_at": "2026-07-06T12:00:00.000Z"
    }
  ]
}
```

## Security properties

- The export file is **not** additionally encrypted — protect it like a password backup.
- Plaintext is recoverable only with the master password (derive keys from `email` +
  `kdf_params`, unwrap `protected_symmetric_key`, decrypt each `ciphertext`).
- Import merges by skipping items whose `id` already exists locally.

## Versioning

- `version: 1` — initial Phase 5 format.
- Future versions may add fields; clients must reject unknown `version` values.
