# Secure Vault

Zero-knowledge, Bitwarden-style password manager — a learning project for Go and DevSecOps.

A runnable React frontend + Go backend wired through an OpenAPI contract, a pure-Go zero-knowledge crypto package (`internal/crypto`), and a PostgreSQL storage layer backed by `sqlc`.

## Architecture

```
Browser (React + TS, :5173) ──/api proxy──► Go API server (net/http, :8080)
        │                                          │
        └─ fetches /api/health                     ├─ OpenAPI routes (generated)
                                                    ├─ Swagger UI at /docs
                                                    └─ PostgreSQL (via sqlc)
```

The OpenAPI spec [`api/openapi.yaml`](api/openapi.yaml) is the **single source of
truth**: `oapi-codegen` generates the Go server interface
(`internal/api/gen/`) and `openapi-typescript` generates the TS client types
(`web/src/api/gen/`). Edit the spec, regenerate, and both sides stay in sync.

## Layout

| Path | Purpose |
|---|---|
| `cmd/server/` | HTTP server entrypoint (hardened `http.Server`) |
| `internal/api/` | Handlers, router, middleware + generated `gen/` code |
| `internal/config/` | Env config, validated at startup |
| `internal/crypto/` | Zero-knowledge crypto core: key hierarchy, Argon2id, XChaCha20-Poly1305 AEAD, key wrapping, item encryption |
| `internal/storage/` | PostgreSQL data layer (sqlc-generated queries for users and items) |
| `api/` | `openapi.yaml` contract + `oapi-codegen.yaml` config |
| `web/` | React + TS frontend (Vite) |
| `db/` | sqlc query definitions |
| `migrations/` | SQL schema migrations |
| `deploy/` | Docker Compose + DB init scripts |

## Crypto core

`internal/crypto` is a pure-Go, network-free package implementing the
zero-knowledge key hierarchy.

```
master password + email(salt) ──Argon2id──► master key
   ├─ HKDF-Expand ──► stretched master key (enc + mac)  → wraps the vault key
   └─ Argon2id (2nd, independent pass) ──► auth hash     → sent to the server
vault key (crypto/rand, 32B) ──XChaCha20-Poly1305──► protected symmetric key
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

Parameters, wire formats, and the security rationale are pinned in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

```sh
go test -race ./internal/crypto/...        # unit + known-answer + property tests
go test -fuzz=FuzzOpen -fuzztime=60s ./internal/crypto/   # fuzz Open on malformed blobs
```

## Run it

Prerequisites: Go 1.22+, Node 18+, PostgreSQL (or Docker for `deploy/docker-compose.yml`).

**Backend** (terminal 1):

```sh
go run ./cmd/server          # or: make run
# → listens on :8080, Swagger UI at http://localhost:8080/docs
```

**Frontend** (terminal 2):

```sh
npm --prefix web install     # first time; approve esbuild's install script if prompted
npm --prefix web run gen:api # generate TS types from the spec
npm --prefix web run dev     # or: make web
# → http://localhost:5173 shows "Backend: ok"
```

> On Windows without `make`, run the commands in the right-hand column above
> directly — they are exactly what each `make` target invokes (see the
> [Makefile](Makefile)).

## Regenerate from the spec

After editing `api/openapi.yaml`:

```sh
go generate ./...            # Go server code  (make generate)
npm --prefix web run gen:api # TS client types (make openapi does both)
```

## Verify

```sh
go build ./... && go vet ./...
curl http://localhost:8080/api/health   # {"status":"ok"}
```
