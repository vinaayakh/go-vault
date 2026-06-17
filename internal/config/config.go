// Package config loads and validates server configuration from the environment.
// It fails fast at startup if a required value is missing or invalid, so the
// server never boots into a half-configured (and potentially insecure) state.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds validated server settings. Secrets (DB DSN, keys) are added in
// later phases; each must be validated here so startup fails loudly if absent.
type Config struct {
	// Addr is the host:port the HTTP server listens on.
	Addr string

	// Read/Write/Idle timeouts harden the server against slow-client DoS
	// (slowloris). See plan/phase-2-server-storage.md §2.4.
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// Load reads configuration from the environment, applies safe defaults, and
// validates the result. It returns an error rather than panicking so the caller
// controls the exit path.
func Load() (*Config, error) {
	port := getenv("PORT", "8080")
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("PORT must be a number, got %q", port)
	}

	cfg := &Config{
		Addr:              ":" + port,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
