// Package api wires the HTTP layer of the Secure Vault server: it implements the
// ServerInterface generated from api/openapi.yaml (see ./gen), mounts those
// routes alongside the Swagger UI docs endpoint, and applies the global
// hardening middleware.
//
// Handlers accept and return only ciphertext + metadata — the server never sees
// plaintext (the zero-knowledge invariant). Real storage and auth arrive in
// Phases 2 and 3; the item handlers are stubs for now.
package api
