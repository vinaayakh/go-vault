# Secure Vault — developer tasks. Run `make help` for the list.
# Targets marked (Phase N) are stubs wired up in a later phase.

BINARY := bin/server
PKG     := ./...

.PHONY: help build run test generate openapi web web-build web-install web-lint lint fmt sec wasm clean tools precommit

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
	@echo "TODO(phase-4): GOOS=js GOARCH=wasm go build -o web/public/crypto.wasm ./cmd/wasm"

clean: ## Remove build artifacts
	rm -rf bin web/dist
