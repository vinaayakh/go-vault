# Secure Vault — developer tasks. Run `make help` for the list.
# Targets marked (Phase N) are stubs wired up in a later phase.

BINARY := bin/server
PKG     := ./...

.PHONY: help build run test generate openapi web web-build web-install lint sec wasm clean

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

lint: ## Run golangci-lint (Phase 0 task 0.3 — config added next)
	@echo "TODO(phase-0): add .golangci.yml and run golangci-lint"

sec: ## Run govulncheck + gosec (Phase 0 task 0.4)
	@echo "TODO(phase-0): wire govulncheck ./... and gosec"

wasm: ## Build the crypto core to WebAssembly (Phase 4)
	@echo "TODO(phase-4): GOOS=js GOARCH=wasm go build -o web/public/crypto.wasm ./cmd/wasm"

clean: ## Remove build artifacts
	rm -rf bin web/dist
