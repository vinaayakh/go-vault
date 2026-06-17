package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/vinaayakh/secure-vault/internal/api/gen"
)

// Server implements gen.ServerInterface — the set of handlers generated from
// api/openapi.yaml. It currently holds only a logger; storage and auth
// dependencies are added in Phases 2 and 3.
type Server struct {
	log *slog.Logger
}

// NewServer constructs the API handler set.
func NewServer(log *slog.Logger) *Server {
	return &Server{log: log}
}

// Ensure *Server satisfies the generated contract at compile time.
var _ gen.ServerInterface = (*Server)(nil)

// GetHealth implements GET /api/health — a no-auth liveness probe.
func (s *Server) GetHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, gen.HealthResponse{Status: "ok"})
}

// ListItems implements GET /api/items. Stub until Phase 2 (storage) + Phase 3 (auth).
func (s *Server) ListItems(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, gen.Error{Error: "items API not implemented yet"})
}

// CreateItem implements POST /api/items. Stub until Phase 2 (storage) + Phase 3 (auth).
func (s *Server) CreateItem(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, gen.Error{Error: "items API not implemented yet"})
}

// writeJSON encodes v as JSON with the given status. Encoding errors are logged
// (not surfaced to the client) since the header is already committed.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}
