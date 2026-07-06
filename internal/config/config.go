// Package config loads and validates server configuration from the environment.
// It fails fast at startup if a required value is missing or invalid, so the
// server never boots into a half-configured (and potentially insecure) state.
package config

import (
	"errors"
	"fmt"
	"net/url"
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
	// (slowloris). See docs/THREAT_MODEL.md.
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

	// AccessTokenDuration is how long the vault_access cookie is valid.
	// Defaults to 15 minutes.
	AccessTokenDuration time.Duration

	// RefreshTokenDuration is how long the vault_refresh cookie is valid.
	// Defaults to 7 days.
	RefreshTokenDuration time.Duration
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

	accessDuration := 15 * time.Minute
	if raw := os.Getenv("ACCESS_TOKEN_DURATION"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("ACCESS_TOKEN_DURATION must be a valid duration (e.g. 15m), got %q", raw)
		}
		accessDuration = d
	}

	refreshDuration := 168 * time.Hour
	if raw := os.Getenv("REFRESH_TOKEN_DURATION"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("REFRESH_TOKEN_DURATION must be a valid duration (e.g. 168h), got %q", raw)
		}
		refreshDuration = d
	}

	// Deprecated: SESSION_DURATION maps to refresh token lifetime for backward compat.
	if raw := os.Getenv("SESSION_DURATION"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("SESSION_DURATION must be a valid duration (e.g. 24h), got %q", raw)
		}
		refreshDuration = d
	}

	allowedOrigin := getenv("ALLOWED_ORIGIN", "http://localhost:5173")

	if !strings.HasPrefix(allowedOrigin, "https://") {
		u, err := url.Parse(allowedOrigin)
		if err != nil {
			return nil, fmt.Errorf("ALLOWED_ORIGIN %q is not a valid URL: %w", allowedOrigin, err)
		}
		host := u.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" && !strings.HasSuffix(host, ".localhost") {
			return nil, fmt.Errorf("ALLOWED_ORIGIN %q uses HTTP with a non-localhost host; set an https:// URL for non-local deployments", allowedOrigin)
		}
	}

	cfg := &Config{
		Addr:                 ":" + port,
		ReadHeaderTimeout:    5 * time.Second,
		ReadTimeout:          15 * time.Second,
		WriteTimeout:         15 * time.Second,
		IdleTimeout:          60 * time.Second,
		DatabaseDSN:          dsn,
		AllowedOrigin:        allowedOrigin,
		AccessTokenDuration:  accessDuration,
		RefreshTokenDuration: refreshDuration,
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
