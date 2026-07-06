# OWASP ASVS L2 — self-assessment (Phase 5)

Mapping of [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) Level 2
controls to Secure Vault v0.4. Status: **Met** / **Partial** / **N/A**.

## V2 Authentication

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| 2.1.1 | User-set passwords | Met | Register + change-password UI; Argon2id KDF |
| 2.2.1 | Anti-automation | Met | Per-IP and per-account login rate limits |
| 2.3.1 | MFA | Met | TOTP + recovery codes (`internal/mfa`) |
| 2.4.1 | Credential recovery | Partial | Recovery codes for 2FA only; no master-password recovery ([RECOVERY.md](RECOVERY.md)) |

## V3 Session management

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| 3.2.1 | Session binding | Met | HttpOnly/Secure/SameSite=Strict cookie |
| 3.3.1 | Session logout | Met | `POST /api/logout` revokes server-side |
| 3.4.1 | Cookie-based session | Met | `vault_session` token hash in DB |

## V4 Access control

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| 4.1.1 | Object-level access | Met | Items scoped by `user_id`; session auth |
| 4.2.1 | CSRF | Met | `X-Vault-CSRF` + SameSite cookie |

## V8 Data protection

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| 8.2.1 | Sensitive data classification | Met | Zero-knowledge threat model |
| 8.3.1 | Sensitive data in memory | Partial | Client clears passwords; Go `crypto.Zero` |
| 8.3.4 | Sensitive data in logs | Met | Audit metadata-only; no secrets in slog |

## V10 Malicious input

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| 10.2.1 | Input validation | Met | `decodeJSON` + `DisallowUnknownFields`; ciphertext validation |
| 10.2.2 | Fuzzing | Met | `internal/crypto/fuzz_test.go`, `internal/api/fuzz_test.go` |

## V14 Configuration

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| 14.2.1 | Build pipeline | Met | CI: SAST, DAST (ZAP), govulncheck, Trivy |
| 14.2.2 | Dependency management | Met | Dependabot; SBOM on release |
| 14.3.1 | Container hardening | Met | Distroless, non-root, read-only compose |

## Open gaps (accepted / future)

- Master-password recovery (by design zero-knowledge).
- Secure sharing (deferred).
- WebAuthn / passkeys (stretch).
- Vendored Swagger UI (CDN in dev docs only).
