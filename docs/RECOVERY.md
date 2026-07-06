# Account recovery policy

Secure Vault is a **zero-knowledge** password manager. The server never stores your
master password, vault key, or item plaintext.

## Lost master password

**If you lose your master password, your vault cannot be recovered.** This is an
intentional security tradeoff: no one — including operators of this service — can
decrypt your data without the password.

## What you can recover

| Asset | Recovery |
|-------|----------|
| **2FA access** | Single-use **recovery codes** generated at 2FA enrollment (store offline) |
| **Vault data** | **Encrypted export** file + master password |
| **Session** | Log in again with master password (+ 2FA if enabled) |

Recovery codes restore **login** when your authenticator is unavailable. They do **not**
replace the master password for decrypting the vault.

## Optional future: recovery key

A future version may offer an explicit, user-consented **recovery key** — a high-entropy
secret shown once at setup, stored offline, and used to re-wrap the vault key. This would
be opt-in and documented separately; it is **not** implemented in v0.

## 2FA interaction

- Disabling 2FA requires a valid TOTP code or an unused recovery code.
- Regenerating recovery codes invalidates all previous codes.

## Recommendations

1. Store an encrypted export in a safe location.
2. Save 2FA recovery codes when enabling TOTP.
3. Use a strong, unique master password (check breach status at registration).

See also [THREAT_MODEL.md](THREAT_MODEL.md) §1 and §11.
