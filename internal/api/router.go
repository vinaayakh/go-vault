package api

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/vinaayakh/secure-vault/internal/api/gen"
	"github.com/vinaayakh/secure-vault/internal/auth"
	"github.com/vinaayakh/secure-vault/internal/config"
	"github.com/vinaayakh/secure-vault/internal/storage"
)

// NewRouter builds the fully-wired HTTP handler: the generated OpenAPI routes,
// the API docs (Swagger UI + raw spec), and the global hardening middleware.
//
// Routing strategy (Go 1.22 ServeMux):
//   - More-specific patterns beat less-specific ones, so unguarded routes
//     registered on the outer mux win over the guarded /api/ subtree.
//   - Health + ready + register + login are unguarded (no auth required).
//   - Items, sync, logout, and user routes are guarded by sessionAuth.
//   - State-changing routes additionally require the X-Vault-CSRF: 1 header.
func NewRouter(log *slog.Logger, store *storage.Store, authMgr *auth.Manager, cfg *config.Config) http.Handler {
	mux := http.NewServeMux()
	srv := NewServer(log, store, authMgr, cfg.SecureCookies)

	// --- Unguarded routes (no session required) ---
	mux.HandleFunc("GET /api/health", srv.GetHealth)
	mux.HandleFunc("GET /api/ready", srv.GetReady)
	mux.HandleFunc("GET /openapi.json", serveSpec)
	mux.HandleFunc("GET /docs", serveSwaggerUI)

	// Auth endpoints: rate-limited inside handlers, but no session required.
	mux.HandleFunc("POST /api/register", chain(
		http.HandlerFunc(srv.PostRegister),
		requireCSRF(),
	).ServeHTTP)
	mux.HandleFunc("POST /api/login", chain(
		http.HandlerFunc(srv.PostLogin),
		requireCSRF(),
	).ServeHTTP)

	// --- Session-guarded routes ---
	// Logout: guarded, state-changing.
	mux.HandleFunc("POST /api/logout", chain(
		http.HandlerFunc(srv.PostLogout),
		sessionAuth(authMgr),
		requireCSRF(),
	).ServeHTTP)

	// User management: guarded, state-changing.
	mux.HandleFunc("DELETE /api/user", chain(
		http.HandlerFunc(srv.DeleteUser),
		sessionAuth(authMgr),
		requireCSRF(),
	).ServeHTTP)
	mux.HandleFunc("PUT /api/user/key", chain(
		http.HandlerFunc(srv.PutUserKey),
		sessionAuth(authMgr),
		requireCSRF(),
	).ServeHTTP)

	// Item CRUD: guarded. GET is read-only (no CSRF needed); POST/PUT/DELETE are state-changing.
	mux.HandleFunc("GET /api/items", chain(
		http.HandlerFunc(srv.ListItems),
		sessionAuth(authMgr),
	).ServeHTTP)
	mux.HandleFunc("POST /api/items", chain(
		http.HandlerFunc(srv.CreateItem),
		sessionAuth(authMgr),
		requireCSRF(),
	).ServeHTTP)
	mux.HandleFunc("PUT /api/items/{id}", chain(
		http.HandlerFunc(withItemID(srv.UpdateItem)),
		sessionAuth(authMgr),
		requireCSRF(),
	).ServeHTTP)
	mux.HandleFunc("DELETE /api/items/{id}", chain(
		http.HandlerFunc(withItemID(srv.DeleteItem)),
		sessionAuth(authMgr),
		requireCSRF(),
	).ServeHTTP)

	// Sync: read-only, session-guarded.
	mux.HandleFunc("GET /api/sync", chain(
		http.HandlerFunc(srv.GetSync),
		sessionAuth(authMgr),
	).ServeHTTP)

	// Global middleware — outermost first (applied to everything).
	return chain(mux,
		requestID(),
		recoverPanic(log),
		logRequests(log),
		limitBody(),
		securityHeaders(),
		cors(cfg.AllowedOrigin),
	)
}

// serveSpec returns the OpenAPI document as JSON so the docs UI always matches
// the deployed contract.
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
// Assets are loaded from a version-pinned CDN for Phase 0 simplicity. Phase 5
// (hardening) should vendor swagger-ui-dist locally and add Subresource Integrity
// hashes so the docs page needs no external origin in the CSP.
//
// We override the global restrictive CSP here: the CDN-hosted Swagger UI requires
// external script/style sources and executes inline JS. This override applies only
// to the /docs route; all API endpoints keep the strict policy.
func serveSwaggerUI(w http.ResponseWriter, r *http.Request) {
	cdn := "https://cdn.jsdelivr.net"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; "+
			"script-src '"+cdn+"' 'unsafe-inline'; "+
			"style-src '"+cdn+"' 'unsafe-inline'; "+
			"img-src 'self' data: '"+cdn+"'; "+
			"connect-src 'self'; "+
			"frame-ancestors 'none'; base-uri 'self'")
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
