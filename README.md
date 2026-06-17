# Secure Vault

Zero-knowledge, Bitwarden-style password manager — a learning project for Go and
DevSecOps. See [`plan/`](plan/README.md) for the phased build plan and the
zero-knowledge architecture.

This repository currently contains the **Phase 0 web-app skeleton**: a runnable
React frontend + Go backend wired through an OpenAPI contract.

## Architecture (Phase 0)

```
Browser (React + TS, :5173) ──/api proxy──► Go API server (net/http, :8080)
        │                                          │
        └─ fetches /api/health                     ├─ OpenAPI routes (generated)
                                                    └─ Swagger UI at /docs
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
| `internal/{crypto,auth,vault,storage}/` | Empty stubs for Phases 1–3 |
| `api/` | `openapi.yaml` contract + `oapi-codegen.yaml` config |
| `web/` | React + TS frontend (Vite) |

## Run it

Prerequisites: Go 1.22+, Node 18+.

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
