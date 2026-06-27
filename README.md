# Secure Vault

Zero-knowledge, Bitwarden-style password manager — a learning project for Go and DevSecOps.

A runnable React frontend + Go backend wired through an OpenAPI contract, a pure-Go zero-knowledge crypto package (`internal/crypto`) compiled to WebAssembly so the browser runs the **exact same audited code** as the server, and a PostgreSQL storage layer backed by `sqlc`.

## Architecture

```
Browser (React + TS, :5173)
  │
  ├─ loads /crypto.wasm (Go crypto, SRI-verified)
  │     all encryption/decryption runs here
  │     server never sees plaintext or vault key
  │
  └── /api proxy ──► Go API server (net/http, :8080)
                           │
                           ├─ OpenAPI routes (generated)
                           ├─ Swagger UI at /docs
                           └─ PostgreSQL (ciphertext at rest only)
```

**Zero-knowledge invariant:** if the database and all server memory leaked, an attacker cannot decrypt any vault item without each user's master password — the server only ever sees ciphertext and an independent auth hash.

The OpenAPI spec [`api/openapi.yaml`](api/openapi.yaml) is the **single source of truth**: `oapi-codegen` generates the Go server interface (`internal/api/gen/`) and `openapi-typescript` generates the TS client types (`web/src/api/gen/`).

## Layout

| Path | Purpose |
|---|---|
| `cmd/server/` | HTTP server entrypoint (hardened `http.Server`) |
| `cmd/wasm/` | WebAssembly entrypoint — exposes `vc*` crypto functions on `globalThis` |
| `cmd/sri/` | CLI tool: computes SHA-384 SRI hash of `crypto.wasm` for integrity enforcement |
| `internal/api/` | Handlers, router, middleware + generated `gen/` code |
| `internal/auth/` | Session management + rate limiting (login/register) |
| `internal/config/` | Env config, validated at startup |
| `internal/crypto/` | Zero-knowledge crypto core: key hierarchy, Argon2id, XChaCha20-Poly1305 AEAD, key wrapping, item encryption |
| `internal/storage/` | PostgreSQL data layer (users, vault_items, sessions) |
| `api/` | `openapi.yaml` contract + `oapi-codegen.yaml` config |
| `web/src/crypto/` | TypeScript wrapper that loads and drives `crypto.wasm` |
| `web/src/context/` | `VaultContext` — holds vault key in memory, drives auto-lock |
| `web/src/components/` | React UI: login, register, vault list, item card, add modal, password generator |
| `web/src/api/` | Typed API client (generated types + hand-written request functions) |
| `web/e2e/` | Playwright end-to-end tests (zero-knowledge assertions) |
| `db/` | sqlc query definitions |
| `migrations/` | SQL schema migrations |
| `deploy/` | Docker Compose + DB init scripts |

## Crypto core

`internal/crypto` is a pure-Go, network-free package implementing the zero-knowledge key hierarchy. It is compiled to WebAssembly for the browser — the same audited, fuzzed code runs on both sides.

```
master password + email (salt) ──Argon2id──► master key
   ├─ HKDF-Expand ──► stretched master key (encKey + macKey)  → wraps the vault key
   └─ Argon2id (2nd, independent pass) ──► auth hash           → sent to the server only
vault key (crypto/rand, 32 B) ──XChaCha20-Poly1305──► protected_symmetric_key (stored in DB)
```

| Function | Purpose |
|---|---|
| `DeriveMasterKey` / `StretchMasterKey` | Argon2id KDF + HKDF-SHA256 subkeys |
| `DeriveAuthHash` / `DeriveServerAuthHash` | Independent auth-hash passes (client + server) |
| `NewVaultKey` / `NewServerSalt` | CSPRNG key + salt generation |
| `Seal` / `Open` | XChaCha20-Poly1305 AEAD (`nonce(24) ‖ ciphertext ‖ tag`) |
| `WrapKey` / `UnwrapKey` | Envelope-encrypt the vault key under the stretched master key |
| `EncryptItem` / `DecryptItem` | JSON-serialize + seal/open a vault item |
| `Zero` / `ConstantTimeEqual` | Memory hygiene + constant-time secret comparison |

Parameters, wire formats, and the security rationale are pinned in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

```sh
go test -race ./internal/crypto/...                          # unit + known-answer + property tests
go test -fuzz=FuzzOpen -fuzztime=60s ./internal/crypto/...  # fuzz Open on malformed blobs
```

## Run it

Prerequisites: Go 1.22+, Node 18+, PostgreSQL (or Docker for `deploy/docker-compose.yml`).

**Build the WASM crypto module first** (one-time, or after any change to `internal/crypto`):

```sh
make wasm
# Builds web/public/crypto.wasm, copies wasm_exec.js, writes web/public/crypto.wasm.sri
```

**Backend** (terminal 1):

```sh
go run ./cmd/server          # or: make run
# → listens on :8080, Swagger UI at http://localhost:8080/docs
```

**Frontend** (terminal 2):

```sh
npm --prefix web install     # first time
npm --prefix web run gen:api # generate TS types from the spec
npm --prefix web run dev     # or: make web
# → http://localhost:5173
```

> On Windows without `make`, run the commands in the right-hand column above directly — they
> are exactly what each `make` target invokes (see the [Makefile](Makefile)).

## Browser security properties

| Property | Implementation |
|---|---|
| Ciphertext only to server | All AEAD encryption runs in `crypto.wasm` before any network call |
| WASM supply-chain integrity | SHA-384 SRI hash in `/crypto.wasm.sri` verified by `fetch()` before instantiation |
| Auto-lock | 5-minute inactivity timer; immediate lock on tab hidden (`visibilitychange`) |
| Clipboard hygiene | Clipboard cleared after 30 seconds on every password copy |
| CSP | `script-src 'self' 'wasm-unsafe-eval'`; no inline scripts; `frame-ancestors 'none'` |
| Vault key in memory only | `vaultKey` held in React state only; never written to `localStorage`, `sessionStorage`, cookies, DOM attributes, or URLs |

## Regenerate from the spec

After editing `api/openapi.yaml`:

```sh
go generate ./...            # Go server code  (make generate)
npm --prefix web run gen:api # TS client types (make openapi does both)
```

## Test

```sh
# Go unit tests
go test -race ./...

# Go integration tests (requires running DB)
go test -race -tags integration ./...

# TypeScript type check
npm --prefix web run typecheck

# Playwright E2E (zero-knowledge assertions — requires running stack)
npm --prefix web run test:e2e
```

The E2E suite intercepts all outbound network requests and asserts that no POST/PUT body contains the master password or any decrypted item plaintext — only opaque Base64 ciphertext reaches the server.

## Verify

```sh
go build ./... && go vet ./...
curl http://localhost:8080/api/health   # {"status":"ok"}
```
