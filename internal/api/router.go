package api

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/vinaayakh/secure-vault/internal/api/gen"
)

// NewRouter builds the fully-wired HTTP handler: the generated OpenAPI routes,
// the API docs (Swagger UI + raw spec), and the global hardening middleware
// applied to everything.
func NewRouter(log *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	// Docs: serve the machine-readable spec and a Swagger UI that renders it.
	mux.HandleFunc("GET /openapi.json", serveSpec)
	mux.HandleFunc("GET /docs", serveSwaggerUI)

	// Generated API routes (GET /api/health, GET|POST /api/items) registered
	// onto the same mux. Returns the mux as an http.Handler.
	handler := gen.HandlerFromMux(NewServer(log), mux)

	// Global middleware — outermost first.
	return chain(handler,
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

	// Avoid direct ResponseWriter writes: parse + re-encode through writeJSON.
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
