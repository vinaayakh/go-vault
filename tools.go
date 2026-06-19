//go:build tools

// Package tools pins build-time tool dependencies so their versions are tracked
// in go.mod and reproducible across machines. It is never compiled into the
// application (guarded by the "tools" build tag).
//
// Run the generators via `make generate` (oapi-codegen) and `make sqlc` (sqlc).
// Note: sqlc requires a Linux/macOS host (wazero WASM allocator does not support
// Windows); run `make sqlc` in CI or WSL.
package tools

import (
	_ "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"
	_ "github.com/sqlc-dev/sqlc/cmd/sqlc"
)
