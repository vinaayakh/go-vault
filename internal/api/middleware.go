package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// maxBodyBytes caps request bodies to defend against memory-exhaustion DoS.
// 1 MiB is generous for ciphertext blobs + metadata; tune per-route later.
const maxBodyBytes = 1 << 20

type ctxKey string

const (
	requestIDKey ctxKey = "request_id"
	// userIDKey carries the acting user's UUID injected by devAuthGuard (Phase 2)
	// or session auth (Phase 3). Handlers retrieve it via userIDFromCtx.
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

// devAuthGuard is the TEMPORARY Phase 2 authentication guard.
// It reads the X-Dev-User header as the acting user UUID and injects it into
// the request context. It is ONLY active when appEnv == "dev" && devAuth == true;
// it hard-fails with 403 in any other environment (fail-closed).
//
// Phase 3 deletes this and replaces it with real session authentication.
func devAuthGuard(appEnv string, devAuth bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if appEnv != "dev" || !devAuth {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "authentication required",
				})
				return
			}
			raw := r.Header.Get("X-Dev-User")
			if raw == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "X-Dev-User header required in dev mode",
				})
				return
			}
			id, err := uuid.Parse(raw)
			if err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "X-Dev-User must be a valid UUID",
				})
				return
			}
			ctx := context.WithValue(r.Context(), userIDKey, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// userIDFromCtx extracts the acting user UUID from the request context.
// Returns the zero UUID and false if not present (should only happen if a route
// was wired without the auth guard — treat as a programming error).
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
