package api

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/vinaayakh/secure-vault/internal/api/gen"
	"github.com/vinaayakh/secure-vault/internal/config"
	"github.com/vinaayakh/secure-vault/internal/storage"
)

// NewRouter builds the fully-wired HTTP handler: the generated OpenAPI routes,
// the API docs (Swagger UI + raw spec), and the global hardening middleware.
//
// Routing strategy (Go 1.22 ServeMux):
//   - More-specific patterns beat less-specific ones, so unguarded routes
//     registered on the outer mux win over the guarded /api/ subtree.
//   - Health + ready are unguarded (orchestrator probes must not require auth).
//   - Items + sync are guarded by the Phase 2 dev-auth guard.
func NewRouter(log *slog.Logger, store *storage.Store, cfg *config.Config) http.Handler {
	mux := http.NewServeMux()
	srv := NewServer(log, store)

	// --- Unguarded routes (no auth required) ---
	// These are registered directly on the outer mux; they win over /api/
	// because Go 1.22 ServeMux uses longest-prefix precedence.
	mux.HandleFunc("GET /api/health", srv.GetHealth)
	mux.HandleFunc("GET /api/ready", srv.GetReady)
	mux.HandleFunc("GET /openapi.json", serveSpec)
	mux.HandleFunc("GET /docs", serveSwaggerUI)

	// --- Guarded routes (Phase 2 dev-auth; Phase 3 → session auth) ---
	// A sub-mux holds these routes; the dev-auth guard wraps it.
	// The sub-mux is mounted under /api/ so it receives all /api/* traffic
	// not already claimed by the more-specific unguarded patterns above.
	protected := http.NewServeMux()
	protected.HandleFunc("GET /api/items", srv.ListItems)
	protected.HandleFunc("POST /api/items", srv.CreateItem)
	protected.HandleFunc("PUT /api/items/{id}", withItemID(srv.UpdateItem))
	protected.HandleFunc("DELETE /api/items/{id}", withItemID(srv.DeleteItem))
	protected.HandleFunc("GET /api/sync", srv.GetSync)

	// Wrap the protected sub-mux with auth, then mount it.
	mux.Handle("/api/", chain(protected, devAuthGuard(cfg.AppEnv, cfg.DevAuth)))

	// Global middleware — outermost first (applied to everything including unguarded routes).
	return chain(mux,
		requestID(),
		recoverPanic(log),
		logRequests(log),
		limitBody(),
	)
}

// serveSpec returns the OpenAPI document (decompressed from the generated embed)
// as JSON, so the docs UI always matches the deployed contract.
func serveSpec(w http.ResponseWriter, r *http.Request) {
	spec, err := gen.GetSpecJSON()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "could not load API spec"})
		return
	}

	var decoded any
	if err := json.Unmarshal(spec, &decoded); err != nil {
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "invalid API spec"})
		return
	}
	writeJSON(w, http.StatusOK, decoded)
}

// serveSwaggerUI renders Swagger UI pointed at /openapi.json.
//
// Assets are loaded from a version-pinned CDN for Phase 0 simplicity. Phase 3
// (security headers / CSP) should vendor swagger-ui-dist locally and/or add
// Subresource Integrity hashes so the docs page needs no external origin.
func serveSwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := swaggerUITmpl.Execute(w, nil); err != nil {
		http.Error(w, "failed to render docs", http.StatusInternalServerError)
	}
}

const swaggerUIVersion = "5.17.14"

var swaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Secure Vault API — Docs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@` + swaggerUIVersion + `/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@` + swaggerUIVersion + `/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({ url: '/openapi.json', dom_id: '#swagger-ui' });
  </script>
</body>
</html>`

var swaggerUITmpl = template.Must(template.New("swagger-ui").Parse(swaggerUIHTML))

// withItemID adapts handlers that require a UUID path parameter to the standard
// http.HandlerFunc signature. It extracts {id} from the ServeMux path value,
// parses it as a UUID, and rejects invalid values with 400 before calling the handler.
func withItemID(h func(http.ResponseWriter, *http.Request, uuid.UUID)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.PathValue("id")
		id, err := uuid.Parse(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, gen.Error{Error: "invalid item id: must be a UUID"})
			return
		}
		h(w, r, id)
	}
}
