# Secure Vault — Threat Model

> **Status:** Living document — STRIDE pass updated through Phase 4.
> **Last updated:** 2026-06-27.
> **Scope:** the secure-vault zero-knowledge password manager (server, database, web client).

This document is revised as the system grows. Each later phase has a checklist item to update
the relevant section here: Phase 1 has filled in the [Cryptographic specification](#8-cryptographic-specification)
(now as-built), Phase 3 expands the [authentication trust boundary](#trust-boundaries), and
Phase 5 adds the audit-log and 2FA considerations.

---

## 1. Purpose & scope

Secure Vault is a Bitwarden-style password manager built on a **zero-knowledge** design: all
encryption and decryption happen on the client, and the server stores and returns **only
ciphertext plus non-secret metadata**. This model exists to reason about what an attacker can
achieve against each component and to record the controls that defend the system.

**In scope:**

- The Go API server (`cmd/server`, `internal/api`) and its HTTP boundary.
- The PostgreSQL datastore (ciphertext at rest, Phase 2).
- The web client (React + TypeScript today; crypto core compiled to WASM in Phase 4).
- The supply chain and CI/CD pipeline that builds and ships the above.

**Out of scope (v1)** — see [§11](#11-assumptions--out-of-scope) for the full list:

- A fully compromised client device (malware, keylogger, hostile browser extension).
- Account recovery / key escrow beyond what Phase 3 defines (lose the master password ⇒ lose
  the vault — this is intentional).
- Secure sharing between users (deferred to Phase 5).

---

## 2. System overview

```
┌─────────────────────────────┐      ┌──────────────────────────┐      ┌────────────────────┐
│  BROWSER (untrusted by srv) │      │  GO API SERVER           │      │  POSTGRESQL        │
│                             │      │  (untrusted for vault    │      │  (untrusted for    │
│  React/TS UI                │      │   confidentiality)       │      │   confidentiality) │
│      │                      │      │                          │      │                    │
│      ▼                      │ HTTPS│  net/http + middleware   │ TCP  │  users             │
│  Crypto core (WASM, P4) ────┼─────▶│  - request id, recovery  ├─────▶│  vault_items       │
│   - Argon2id KDF            │ JSON │  - body limit, logging   │      │  sessions (P3)     │
│   - XChaCha20-Poly1305      │      │  - auth/session (P3)     │      │                    │
│   - key wrapping            │      │  stores/serves           │      │  CIPHERTEXT +      │
│                             │◀─────┤  ciphertext only         │◀─────┤  metadata ONLY     │
│  master password           │      │                          │      │                    │
│  NEVER leaves the browser   │      │  never sees plaintext    │      │  never sees keys   │
└─────────────────────────────┘      └──────────────────────────┘      └────────────────────┘
        TRUST ZONE A                       TRUST ZONE B                     TRUST ZONE C
```

**What crosses each boundary:**

- **Browser → Server:** the derived *auth hash* (never the password), the *protected
  symmetric key* (wrapped vault key), KDF params, and item *ciphertext* + metadata. All
  Base64 in JSON over HTTPS.
- **Server → Database:** the same opaque ciphertext and the server-side hash of the auth hash.
  No keys, no plaintext.
- **Server → Browser:** ciphertext, the protected symmetric key, and KDF params so the client
  can re-derive keys and unlock locally.

The crucial property: **encryption keys and plaintext exist only inside Trust Zone A.**

---

## 3. Assets

Ranked by sensitivity. "Exposure impact" assumes the attacker obtains the asset.

| Asset | Lives in | Who may legitimately see it | Exposure impact |
|---|---|---|---|
| **Master password** | Browser memory only (Zone A) | The user | Catastrophic — derives every key. **Never transmitted or stored anywhere.** |
| **Master key / stretched master key** | Browser memory only (Zone A) | The user's client | Catastrophic — unwraps the vault key. Derived from the master password; never leaves Zone A. |
| **Vault key** | Browser memory only (Zone A) | The user's client | Catastrophic — decrypts every item. Stored only in *wrapped* form (see below). |
| **Vault items (plaintext)** | Browser memory only (Zone A) | The user | Full credential disclosure for affected items. |
| **Vault items (ciphertext)** | DB + server + wire (Zones B/C) | Server, DB, network | Low on its own — AEAD ciphertext is opaque without the vault key. Metadata (`item_type`, `updated_at`) leaks coarse usage patterns. |
| **Protected symmetric key** (wrapped vault key) | DB + server + wire | Server, DB, network | Low alone — useless without the stretched master key, which never leaves Zone A. |
| **Master-password auth hash** | Wire (login), then hashed server-side | Server (transiently) | Cannot decrypt anything (separate KDF pass). If stolen in transit it could be replayed to authenticate ⇒ TLS + server-side re-hashing required. |
| **Server-side auth-hash hash** (`Argon2id(authHash)` + per-user salt) | DB (Zone C) | Server, DB | Low — a memory-hard hash of a high-entropy value; not directly usable. |
| **KDF params** (`memory_kib`, `iterations`, …) | DB + wire | Everyone (not secret) | Not sensitive; required to re-derive keys. Integrity matters (tampering could weaken derivation). |
| **Session / refresh tokens** (Phase 3) | Cookie (Zone A) + DB (Zone C) | The user, server | Account takeover if stolen ⇒ HttpOnly/Secure/SameSite cookies + server-side revocation. |
| **Server logs** | Server (Zone B) | Operators | Must contain **no** secrets, passwords, keys, or ciphertext-decrypting material. Request IDs only. |

---

## 4. Trust boundaries

1. **Browser ↔ Server (Zone A ↔ B):** crossed over HTTPS, mediated by the OpenAPI contract
   (`api/openapi.yaml`). The server is **untrusted for the confidentiality of vault contents**
   — it is treated as an honest-but-curious (and potentially breached) host. Only ciphertext,
   wrapped keys, and the auth hash cross here.
2. **Server ↔ Database (Zone B ↔ C):** the database is likewise **untrusted for
   confidentiality**. It holds ciphertext and hashed credentials only; a full DB dump must not
   reveal any vault plaintext.
3. **In-browser JS ↔ WASM crypto core (within Zone A, Phase 4):** the WASM module is the only
   component that handles raw keys and plaintext. The surrounding JS passes the master password
   in and gets ciphertext/plaintext out; keys never leave the WASM/JS heap of the user's tab.
   **Trust assumption (new in Phase 4):** the browser trusts that the JS and WASM served by the
   origin are authentic (a malicious server operator could serve modified code that exfiltrates
   keys). Mitigations in place: Content-Security-Policy restricts resource origins; Subresource
   Integrity on `crypto.wasm` (SHA-384 hash pinned at build time) means a tampered WASM binary
   fails to load. A compromised server could still replace the JS bundle — this is an accepted
   residual risk documented in §10.
4. **Developer/CI ↔ production artifact:** the supply-chain boundary. Source, dependencies, and
   the container image must be integrity-checked before they run (see STRIDE → Tampering).

---

## 5. The zero-knowledge invariant

> **Primary security property — defend it in every phase:** if the database and all server
> memory leaked, an attacker still could not decrypt any vault item without each user's master
> password.

Design choices that uphold it:

- **Envelope encryption.** A random per-user **vault key** encrypts every item; the **master
  key** (derived from the password) wraps only the vault key. Changing the master password
  re-wraps the vault key and leaves item ciphertext untouched.
- **Two independent KDF passes.** The encryption key path and the authentication-hash path are
  separate derivations, so the value sent to the server for login (the auth hash) **cannot**
  reconstruct the encryption key.
- **Client-side-only crypto.** One pure-Go crypto implementation, compiled to WASM for the
  browser (Phase 4). The server has no decryption code path and no key material.
- **Ciphertext-only contract.** `api/openapi.yaml` encodes the invariant directly: `Item` and
  `NewItem` carry Base64 `ciphertext` + metadata and nothing else.

Any change that would let the server, DB, or network observer decrypt an item **breaks this
invariant** and must be rejected in review.

---

## 6. STRIDE analysis

Each row: threat → affected asset/boundary → mitigation → status (✅ in place / 🔜 planned
phase). "In place" controls already exist in the repo (CI pipeline, distroless image, hardened
server middleware, the contract); planned controls are tagged with their phase.

### Spoofing (authenticity)

| Threat | Asset / boundary | Mitigation | Status |
|---|---|---|---|
| Attacker impersonates a user | Browser↔Server | Auth via derived auth-hash + server-side Argon2id verify with `subtle.ConstantTimeCompare`; HttpOnly/Secure/SameSite=Strict session cookies; rate limiting + account lockout | ✅ Phase 3 |
| Attacker impersonates the server (MITM) | Browser↔Server | HSTS (`max-age=63072000; includeSubDomains; preload`); CORS locked to `ALLOWED_ORIGIN` (no wildcard) | ✅ Phase 3 |
| Forged GitHub Action / base image substituted into the build | Supply chain | All Actions pinned by commit SHA; base images pinned by digest in `deploy/Dockerfile` | ✅ in place |

### Tampering (integrity)

| Threat | Asset / boundary | Mitigation | Status |
|---|---|---|---|
| Modify ciphertext at rest or in transit | Vault items | AEAD (XChaCha20-Poly1305) — any bit flip fails authentication on `Open` | ✅ in place (`internal/crypto`, tamper- + fuzz-tested) |
| Tamper with KDF params to weaken derivation | KDF params | Versioned params validated on use (`KDFParams.validate`, `:v1:` HKDF labels), never silently reinterpreted; binding to the user row lands in Phase 2 | ✅ Phase 1 (versioning/validation) / 🔜 Phase 2 (bound to user row) |
| Malicious dependency or poisoned image | Supply chain | `govulncheck`, Trivy image scan, Dependabot, SBOM (syft), gosec/CodeQL/semgrep in CI | ✅ in place (Dependabot 🔜 0.5) |
| Cross-site request forces a state change | Browser↔Server | SameSite=Strict cookie (primary) + `X-Vault-CSRF: 1` custom header check on all state-changing routes (secondary) | ✅ Phase 3 |

### Repudiation (accountability)

| Threat | Asset / boundary | Mitigation | Status |
|---|---|---|---|
| User/attacker denies an action | Server | Structured request logging with request IDs (`internal/api/middleware.go`); no secrets logged | ✅ baseline in place |
| No durable record of security-relevant events | Server/DB | Append-only audit log (logins, item changes, key rotations) | 🔜 Phase 5 |

### Information disclosure (confidentiality)

| Threat | Asset / boundary | Mitigation | Status |
|---|---|---|---|
| DB dump reveals vault contents | DB | Zero-knowledge invariant — only ciphertext + wrapped keys stored | ✅ by design / enforced from Phase 2 |
| Server memory scrape reveals plaintext/keys | Server | Server never receives the password, keys, or plaintext; decryption code path does not exist server-side | ✅ by design |
| Secrets committed to git | Source | `gitleaks` in pre-commit **and** CI; `detect-private-key` hook | ✅ in place |
| Master password reaches the server | Browser↔Server | Client sends only the derived auth hash; contract has no password field | ✅ by design (verified Phase 3) |
| User enumeration via register/login responses | Browser↔Server | Uniform 201 for register regardless of duplicate email; dummy Argon2id hash on unknown-email login to equalize timing | ✅ Phase 3 |
| Metadata leakage (`item_type`, timestamps) | Vault items | Accepted residual risk for v1; documented; minimized to non-secret category hints | ✅ documented |
| Verbose errors leak internals | Server | Generic `Error` schema; client-safe messages only | ✅ in place |

### Denial of service (availability)

| Threat | Asset / boundary | Mitigation | Status |
|---|---|---|---|
| Oversized request bodies exhaust memory | Server | Body-size limit middleware (`internal/api/middleware.go`) | ✅ in place |
| Slowloris / hung connections | Server | Read/Write/Idle timeouts on `http.Server` | ✅ baseline (extended Phase 2) |
| Brute-force login floods | Auth | Per-IP (10/15 min) + per-account (5/15 min) sliding-window rate limiting in `internal/auth`; returns 429 | ✅ Phase 3 |
| Panic crashes the process | Server | Panic-recovery middleware | ✅ in place |
| Expensive Argon2id used as a CPU/memory amplifier | Auth | Rate-limit `/register` (5/h per IP) and `/login`; bounded KDF params | ✅ Phase 3 |

### Elevation of privilege (authorization)

| Threat | Asset / boundary | Mitigation | Status |
|---|---|---|---|
| User reads/edits another user's items (IDOR) | Items API | All item queries scoped to the session's authenticated user id; cross-user access returns ErrNotFound | ✅ Phase 2/3 |
| Temporary `X-Dev-User` dev guard abused | Server | Dev guard removed entirely in Phase 3; session auth (`sessionAuth` middleware) is the only path | ✅ Phase 3 |
| Container breakout / root escalation | Runtime | Distroless base, no shell/package manager, runs as `nonroot` (uid 65532) in `deploy/Dockerfile` | ✅ in place |
| SQL injection grants data access | DB | Parameterized queries via pgx ($1, $2, …); no string-built SQL in any repo method | ✅ Phase 2 |

---

## 7. Existing controls (Phase 0 baseline)

For reference, the controls already enforced by the repo:

- **Pipeline (`.github/workflows/ci.yml`):** build+test (`-race`), golangci-lint (gosec),
  govulncheck, CodeQL, semgrep, gitleaks, syft SBOM, ESLint/web build, Trivy image scan.
- **Pre-commit (`.pre-commit-config.yaml`):** gitleaks, gofmt/goimports, go vet, golangci-lint,
  ESLint, `detect-private-key`, large-file and merge-conflict guards.
- **Supply chain:** every Action pinned by SHA; base images pinned by digest.
- **Container:** distroless, multi-stage, static (CGO disabled), nonroot.
- **Server:** request-id, panic-recovery, body-limit, and structured-logging middleware.

---

## 8. Cryptographic specification

> **Status: as-built (Phase 1).** The values below match the implementation in
> `internal/crypto` and the decisions pinned in `plan/phase-1-crypto-core.md`
> ("Wire formats & parameters"). They are verified by the package test suite, including
> known-answer tests: Argon2id is pinned by a regression vector, and `Open` is checked against
> the published XChaCha20-Poly1305 vector from draft-irtf-cfrg-xchacha-03 §A.3.1. Round-trip and
> tamper behaviour is covered by property tests and `go test -fuzz` targets.
>
> **Memory hygiene (honest limits).** Key and plaintext buffers are zeroed (`crypto.Zero`) as
> soon as they are no longer needed, and secret comparisons use constant time
> (`crypto.ConstantTimeEqual` over `crypto/subtle`). Go's garbage collector may nonetheless copy
> a buffer's backing array before it is wiped, so zeroing narrows — but does not eliminate — the
> window in which a secret sits in process memory. This is an accepted residual risk in v1.

- **Key hierarchy:** `Argon2id(masterPassword, salt=email)` → **master key** →
  `HKDF-Expand` → **stretched master key** (enc + mac); a **second, independent**
  `Argon2id(masterKey, salt=masterPassword)` → **auth hash** (sent to server). A random
  `crypto/rand` 32-byte **vault key** encrypts items and is wrapped (`Seal`) by the stretched
  master key → **protected symmetric key** (stored server-side).
- **KDF:** Argon2id, target `m=64 MiB (memory_kib=65536), t=3, p=1` (OWASP min
  `m=19 MiB, t=2, p=1`); `version=19` (0x13).
- **KDF salt:** the user's email, normalized (trim + lowercase; no plus/dot stripping). One
  canonical normalization function used client- and server-side.
- **AEAD cipher:** XChaCha20-Poly1305 (24-byte/192-bit random nonce — safe for long-lived
  keys). AES-256-GCM is documented only as a *possible future* cipher behind a 1-byte algorithm
  tag; v1 has exactly one cipher and does not branch at runtime.
- **AEAD blob layout:** `nonce(24) || ciphertext || tag`, Base64-encoded at the API boundary.
- **HKDF context labels (versioned, part of the contract):** `"secure-vault:v1:enc"` and
  `"secure-vault:v1:mac"`.
- **Server-side auth-hash storage:** a **third** Argon2id pass over the client auth hash with
  its **own per-user random 16-byte salt** (`crypto/rand`, not the email), suggested
  `m=19 MiB, t=2, p=1`; verified with `subtle.ConstantTimeCompare`.
- **Encoding:** Base64 (std, padded) for ciphertext, protected key, and auth hash on the wire;
  raw `[]byte` internally.
- **Versioning:** KDF params (`version`) and HKDF labels (`:v1:`) carry the scheme version. Any
  change to params, labels, or cipher is a new version; old data is read with its stored params
  and never silently reinterpreted.

---

## 9. Authentication & session design (Phase 3)

### Auth hash flow

```
CLIENT                                     SERVER
──────                                     ──────
masterPassword + email(salt)
  ──Argon2id──▶ masterKey (32 B)
       ├─ HKDF-Expand ──▶ encKey / macKey   (local only, never sent)
       └─ Argon2id(masterKey, password)
             ──▶ authHash (32 B)            ──HTTPS──▶ DeriveServerAuthHash(authHash, randomSalt)
                                                         ──▶ serverHash (32 B) stored in DB
```

**What the server stores:** `Argon2id(clientAuthHash, perUserRandomSalt, m=19 MiB, t=2, p=1)`.
This is a memory-hard hash of a 32-byte high-entropy value — not a password. The server
cannot reconstruct the encryption key from it. Server params are pinned at registration and
not re-computed on every login (the client auth hash is already 32-byte random material, so
the server pass defends the at-rest hash, not a low-entropy password).

**At login:** the server re-derives the candidate hash with the stored salt and params, then
uses `subtle.ConstantTimeCompare` to verify — preventing timing-based enumeration.

**On unknown email:** a dummy `DeriveServerAuthHash` call runs before returning 401, equalizing
timing so an observer cannot distinguish "email not found" from "wrong password."

### Session cookie attributes

| Attribute | Value | Why |
|-----------|-------|-----|
| `HttpOnly` | true | Blocks JS from reading the cookie (XSS defense) |
| `Secure` | true | Cookie only sent over HTTPS |
| `SameSite` | Strict | Blocks cross-site request forgery (primary CSRF defense) |
| `Path` | / | Sent on all API paths |
| `MaxAge` | 86400 (24 h) | Time-bounded sessions; no indefinite-lived tokens |

**Session token storage:** 32-byte `crypto/rand` → hex string in cookie; SHA-256 hash stored
in DB. A DB leak of the `sessions` table cannot be directly replayed.
**Server-side revocation:** sessions are stored in the `sessions` table so logout (`DELETE`)
and account deletion (`DELETE * WHERE user_id`) are immediate — no need to wait for expiry.

### Rate limiting

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /api/login` | 10 attempts | 15 minutes | Client IP |
| `POST /api/login` | 5 attempts | 15 minutes | Account (email) |
| `POST /api/register` | 5 attempts | 1 hour | Client IP |

Implemented in `internal/auth.RateLimiter` as an in-memory sliding-window counter (no
external dep). Counters are shared across all goroutines (sync.Mutex). On successful login
both IP and account counters are reset.

**Residual risk:** rate-limit state is in-process memory — it resets on server restart and
does not share across replicas in a multi-instance deployment. For v1 (single instance) this
is acceptable. Phase 5 can replace with Redis-backed counters if needed.

### CSRF defenses

Two independent layers:
1. **SameSite=Strict cookie** — the browser will not attach the `vault_session` cookie to
   cross-site requests, so any cross-site POST cannot be authenticated.
2. **`X-Vault-CSRF: 1` custom header** — all state-changing routes (`POST`, `PUT`, `DELETE`)
   require this header. Browsers cannot include custom headers in cross-origin requests without
   a CORS preflight; since the preflight checks the `Access-Control-Allow-Origin` against
   `ALLOWED_ORIGIN` (not `*`), a cross-site attacker cannot forge the header.

### Security headers added in Phase 3

| Header | Value | Defense |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Prevents downgrade to HTTP |
| `X-Content-Type-Options` | `nosniff` | Blocks MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking via framing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer leakage |
| `Content-Security-Policy` | `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; …` | Restricts resource loading; `'wasm-unsafe-eval'` required to instantiate WASM (Phase 4); blocks inline scripts |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Disables unneeded browser features |

---

## 10. Browser key handling (Phase 4)

Phase 4 compiles `internal/crypto` to WebAssembly (`crypto.wasm`) and integrates it into the
React app. The following controls enforce the zero-knowledge invariant on the client side.

### Key lifecycle

| Stage | Key material | Storage | Cleared when |
|---|---|---|---|
| Master key (derivation) | In JS closure during login/register | Volatile — GC'd after use | Function returns |
| Auth hash | In JS closure, sent as Base64 string | Volatile | Sent to server, not retained |
| Stretched master key (encKey/macKey) | In JS closure | Volatile — GC'd after unwrap | Function returns |
| Vault key | React state (`VaultContext`) | In-memory only, never written to any storage API | Auto-lock / logout / page refresh |

**Invariant:** no key material is ever written to `localStorage`, `sessionStorage`,
`IndexedDB`, `Cookie` (JS-accessible), URL parameters, or the DOM.

### Auto-lock

The vault auto-locks (clears `vaultKey` from React state) in two cases:
1. **Inactivity timeout (5 min):** a timer resets on `mousemove`, `keydown`, `click`,
   `touchstart`. When it fires, the vault key is cleared and the user returns to the login form.
2. **Tab hidden:** `visibilitychange → hidden` triggers an immediate lock, preventing keys from
   sitting in memory while the browser is idle in the background.

A page refresh always clears memory — the user must re-enter the master password.

### Clipboard hygiene

When the user copies a vault item's password, the clipboard is programmatically cleared after
30 seconds via `navigator.clipboard.writeText("")`. This limits the window in which a
clipboard sniffer can retrieve a secret.

### Subresource Integrity (SRI) for `crypto.wasm`

`crypto.wasm` is the supply-chain trust anchor for the zero-knowledge claim. Any tampered
binary that exfiltrates keys before encrypting would silently violate the model.

`make wasm` generates a SHA-384 hash of the compiled WASM binary into `web/public/crypto.wasm.sri`.
The WASM loader (`web/src/crypto/service.ts`) fetches `crypto.wasm` with the `integrity`
option, causing the browser to verify the hash before executing the binary. A mismatched hash
causes the fetch to fail with a network error and the app stays locked.

**Residual gap:** SRI covers `crypto.wasm` but not the React/JS bundle. A compromised server
could still serve modified JS — see §10 for the accepted residual risk.

### XSS defenses

- React's JSX template system escapes output by default; `dangerouslySetInnerHTML` is not used
  anywhere in the vault UI.
- No inline `<script>` tags — the CSP `script-src 'self'` directive blocks them.
- Item field values (name, username, password, URL) are rendered as React text nodes, not
  injected as HTML.

---

## 11. Assumptions & out-of-scope

**Assumptions:**

- The user's device and browser are **trusted and uncompromised** (no malware, keylogger, or
  hostile extension). The model does not defend against an attacker who already controls
  Zone A.
- TLS is correctly terminated and certificates are validated (HSTS enforced from Phase 3).
- The user chooses a sufficiently strong master password; a client-side strength check
  (Phase 3) nudges this but cannot guarantee it.
- `crypto/rand` (CSPRNG) is the only randomness source for keys and salts — never `math/rand`.

**Out of scope for v1:**

- Account recovery / key escrow — losing the master password means losing the vault, by design.
- Secure item sharing between users (Phase 5).
- A fully malicious server operator who modifies the served **JS bundle** to exfiltrate keys
  at runtime — Subresource Integrity on `crypto.wasm` prevents tampered WASM binary, but the
  React/JS entry point cannot self-attest. Signed releases and a browser extension could close
  this gap (Phase 5 candidate).
- Side-channel attacks against the host (timing, cache, power) beyond constant-time comparisons
  in the crypto path.
- Hardware security modules / passkeys (TOTP 2FA arrives in Phase 5).

---

## 12. References

- `plan/README.md` — architecture and the zero-knowledge invariant.
- `plan/phase-0-foundations.md` — this phase's tasks and DoD.
- `plan/phase-1-crypto-core.md` — crypto primitives, wire formats, parameters (source for §8).
- `plan/phase-2-server-storage.md` — DB schema, storage layer, dev-auth guard.
- `plan/phase-3-auth.md` — auth, sessions, rate limiting, security headers, CSRF.
- `api/openapi.yaml` — the API contract that encodes the ciphertext-only invariant.
- `deploy/Dockerfile`, `.github/workflows/ci.yml`, `.pre-commit-config.yaml` — the controls
  in §7.
