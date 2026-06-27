# Secure Vault — developer tasks. Run `make help` for the list.
# Targets marked (Phase N) are stubs wired up in a later phase.

BINARY := bin/server
PKG     := ./...

# Load .env if present (for DATABASE_URL, APP_ENV, etc.).
-include .env
export

.PHONY: help build run test test-integration generate openapi web web-build web-install web-lint lint fmt sec wasm clean tools precommit db-up db-down migrate-up migrate-down sqlc grant-app-role

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Compile all Go packages and the server binary
	go build $(PKG)
	go build -o $(BINARY) ./cmd/server

run: ## Run the API server (PORT overridable, default 8080)
	go run ./cmd/server

test: ## Run Go tests with the race detector
	go test -race $(PKG)

test-integration: ## Run integration tests (requires TEST_DATABASE_URL env var)
	go test -race -tags integration ./internal/storage/...

generate: ## Regenerate code from go:generate directives (oapi-codegen)
	go generate $(PKG)

openapi: generate ## Regenerate Go + TS clients from api/openapi.yaml (single source of truth)
	npm --prefix web run gen:api

web-install: ## Install frontend dependencies
	npm --prefix web install

web: ## Run the React dev server (proxies /api to :8080)
	npm --prefix web run dev

web-build: ## Type-check and build the frontend for production
	npm --prefix web run build

web-lint: ## Lint the frontend (ESLint, config in web/eslint.config.js)
	npm --prefix web run lint

tools: ## Install dev tools used by pre-commit (goimports, golangci-lint)
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

precommit: ## Run all pre-commit hooks against the whole repo
	pre-commit run --all-files

fmt: ## Format Go source (gofmt + goimports)
	gofmt -l -w .
	goimports -l -w .

lint: ## Run golangci-lint (config in .golangci.yml)
	golangci-lint run

sec: ## Run govulncheck + gosec (Phase 0 task 0.4) — mirrors the CI vuln + lint jobs
	go run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)
	golangci-lint run --enable-only gosec

wasm: ## Build the crypto core to WebAssembly (Phase 4)
	GOOS=js GOARCH=wasm go build -o web/public/crypto.wasm ./cmd/wasm
	@cp "$$(go env GOROOT)/misc/wasm/wasm_exec.js" web/public/ 2>/dev/null || \
	 cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" web/public/
	go run ./cmd/sri web/public/crypto.wasm > web/public/crypto.wasm.sri
	@echo "Built crypto.wasm — SRI hash: $$(cat web/public/crypto.wasm.sri)"

db-up: ## Start PostgreSQL via Docker Compose
	docker compose -f deploy/docker-compose.yml up -d

db-down: ## Stop and remove PostgreSQL container (data volume preserved)
	docker compose -f deploy/docker-compose.yml down

migrate-up: ## Apply all pending migrations (requires DATABASE_SUPERUSER_URL)
	migrate -path migrations -database "$(DATABASE_SUPERUSER_URL)" up

migrate-down: ## Roll back the last migration (requires DATABASE_SUPERUSER_URL)
	migrate -path migrations -database "$(DATABASE_SUPERUSER_URL)" down 1

grant-app-role: ## Grant least-privilege DML access to vault_app after migration
	psql "$(DATABASE_SUPERUSER_URL)" -f deploy/grant-app-role.sql

sqlc: ## Regenerate storage/sqlcgen from db/queries (requires sqlc; run on Linux in CI)
	sqlc generate

clean: ## Remove build artifacts
	rm -rf bin web/dist
