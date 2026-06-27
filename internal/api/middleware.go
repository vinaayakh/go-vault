package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/vinaayakh/secure-vault/internal/auth"
)

// maxBodyBytes caps request bodies to defend against memory-exhaustion DoS.
// 1 MiB is generous for ciphertext blobs + metadata; tune per-route later.
const maxBodyBytes = 1 << 20

type ctxKey string

const (
	requestIDKey ctxKey = "request_id"
	// userIDKey carries the acting user's UUID injected by sessionAuth.
	// Handlers retrieve it via userIDFromCtx.
	userIDKey ctxKey = "user_id"
)

// Middleware is the standard net/http decorator shape.
type Middleware func(http.Handler) http.Handler

// chain applies middlewares so the first listed runs outermost (first in, last out).
func chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// requestID attaches a random correlation ID to each request, exposed via the
// X-Request-ID response header and the context (for log correlation).
func requestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := newRequestID()
			w.Header().Set("X-Request-ID", id)
			ctx := context.WithValue(r.Context(), requestIDKey, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// recoverPanic converts a handler panic into a generic 500 (no internals leaked)
// and logs the failure with the request ID for correlation.
func recoverPanic(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic recovered",
						"request_id", r.Context().Value(requestIDKey),
						"panic", rec,
						"path", r.URL.Path,
					)
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// limitBody enforces a maximum request body size via http.MaxBytesReader.
func limitBody() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// logRequests emits one structured access log per request. It logs method, path,
// status, duration, and request ID — never bodies, query secrets, or headers,
// per the logging-hygiene policy (no secrets in logs).
func logRequests(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			log.Info("request",
				"request_id", r.Context().Value(requestIDKey),
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// statusWriter captures the response status code for logging.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// sessionAuth validates the vault_session cookie on every protected request.
// On success it injects the user UUID into the context so handlers can retrieve
// it with userIDFromCtx. Returns 401 on any failure (no distinction between
// missing, expired, or invalid — avoids information leaks).
func sessionAuth(mgr *auth.Manager) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(auth.CookieName)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
				return
			}

			sess, err := mgr.ValidateSession(r.Context(), cookie.Value)
			if errors.Is(err, auth.ErrSessionInvalid) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
				return
			}
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, sess.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// securityHeaders adds the OWASP-recommended response headers to every response.
// HSTS, CSP, nosniff, frame-ancestors, and Referrer-Policy are all set here.
// The Swagger UI CDN requires relaxing CSP for /docs — handled in the route itself.
func securityHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			// HSTS: 2 years, include subdomains, eligible for preload list.
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			// Restrictive CSP: allow only same-origin resources; no inline scripts.
			// 'wasm-unsafe-eval' is required by Chrome/Firefox to instantiate WebAssembly
			// modules fetched from the same origin (Phase 4 crypto.wasm).
			h.Set("Content-Security-Policy",
				"default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "+
					"connect-src 'self'; img-src 'self' data:; form-action 'self'; "+
					"frame-ancestors 'none'; base-uri 'self'")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			next.ServeHTTP(w, r)
		})
	}
}

// cors restricts cross-origin requests to the single configured frontend origin.
// Credentials (cookies) are allowed because session cookies travel on every request.
func cors(allowedOrigin string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", allowedOrigin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Vary", "Origin")

			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, X-Vault-CSRF")
				h.Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// requireCSRF rejects state-changing requests (POST/PUT/DELETE) that lack the
// X-Vault-CSRF: 1 custom header. Browsers cannot send custom headers in
// cross-origin requests without a CORS preflight, so this blocks CSRF even
// when SameSite=Strict is not supported. GET/HEAD/OPTIONS are exempt.
func requireCSRF() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if r.Header.Get("X-Vault-CSRF") != "1" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "CSRF check failed"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// userIDFromCtx extracts the acting user UUID from the request context.
// Returns the zero UUID and false if not present (should only happen if a route
// was wired without sessionAuth — treat as a programming error).
func userIDFromCtx(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read never fails on supported platforms; fall back to a timestamp.
		return time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b[:])
}
