//go:build generate

// This file holds repo-wide `go generate` directives. It lives at the repo root
// so `go generate ./...` runs them with the working directory set to the module
// root, keeping all paths root-relative and unambiguous. The `generate` build
// tag (never set in normal builds) keeps it out of `go build` / `go test`, while
// `go generate` still scans it for directives.
//
// Run via `make generate`.
package tools

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml
