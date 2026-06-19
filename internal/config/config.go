// Package config loads and validates server configuration from the environment.
// It fails fast at startup if a required value is missing or invalid, so the
// server never boots into a half-configured (and potentially insecure) state.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
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

	// AppEnv distinguishes the deployment environment. Only "dev" enables the
	// temporary dev-auth guard (Phase 2). Any other value (including "prod") is
	// treated as production — the guard is hard-disabled regardless of DevAuth.
	AppEnv string

	// DevAuth enables the X-Dev-User guard ONLY when AppEnv == "dev".
	// Hard-forced false in any non-dev environment (fail-closed).
	DevAuth bool
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

	appEnv := getenv("APP_ENV", "prod")

	devAuth := appEnv == "dev" && os.Getenv("DEV_AUTH") == "on"

	cfg := &Config{
		Addr:              ":" + port,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		DatabaseDSN:       dsn,
		AppEnv:            appEnv,
		DevAuth:           devAuth,
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
