// Package config loads and validates server configuration from the environment.
// It fails fast at startup if a required value is missing or invalid, so the
// server never boots into a half-configured (and potentially insecure) state.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds validated server settings. Secrets (DB DSN, keys) must be set
// via environment variables; hard-coded defaults only for non-secret values.
type Config struct {
	// Addr is the host:port the HTTP server listens on.
	Addr string

	// Read/Write/Idle timeouts harden the server against slow-client DoS
	// (slowloris). See plan/phase-2-server-storage.md §2.4.
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration

	// DatabaseDSN is the PostgreSQL connection string. Required; startup fails
	// if absent. Example: postgres://user:pass@localhost:5432/vault?sslmode=disable
	DatabaseDSN string

	// AllowedOrigin is the single frontend origin allowed by CORS.
	// Defaults to http://localhost:5173 (Vite dev server).
	AllowedOrigin string

	// SecureCookies controls whether session cookies carry the Secure flag.
	// Derived from AllowedOrigin: true when the origin is HTTPS, false for HTTP
	// (allows cookie to be sent in plain-HTTP local dev flows).
	SecureCookies bool

	// SessionDuration is how long a session cookie is valid.
	// Defaults to 24 hours.
	SessionDuration time.Duration
}

// Load reads configuration from the environment, applies safe defaults, and
// validates the result. It returns an error rather than panicking so the caller
// controls the exit path.
func Load() (*Config, error) {
	port := getenv("PORT", "8080")
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("PORT must be a number, got %q", port)
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, errors.New("DATABASE_URL is required but not set")
	}

	sessionDuration := 24 * time.Hour
	if raw := os.Getenv("SESSION_DURATION"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("SESSION_DURATION must be a valid duration (e.g. 24h), got %q", raw)
		}
		sessionDuration = d
	}

	allowedOrigin := getenv("ALLOWED_ORIGIN", "http://localhost:5173")

	cfg := &Config{
		Addr:              ":" + port,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		DatabaseDSN:       dsn,
		AllowedOrigin:     allowedOrigin,
		SecureCookies:     strings.HasPrefix(allowedOrigin, "https://"),
		SessionDuration:   sessionDuration,
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
