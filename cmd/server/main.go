// Command server is the Secure Vault HTTP API entrypoint. It loads and validates
// configuration, opens the database pool, builds the hardened http.Server, and
// serves the OpenAPI routes plus Swagger UI docs.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vinaayakh/secure-vault/internal/api"
	"github.com/vinaayakh/secure-vault/internal/config"
	"github.com/vinaayakh/secure-vault/internal/storage"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Keep os.Exit confined to main with no pending defers; all cleanup lives in
	// run() so deferred store.Close()/cancel() always execute.
	if err := run(log); err != nil {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// run wires up config, database, and HTTP server, then blocks until an interrupt
// triggers a graceful shutdown. It returns the first fatal error, or nil on clean exit.
func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Open and verify the database connection before accepting traffic.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := storage.New(ctx, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer store.Close()

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.NewRouter(log, store, cfg),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("ok", "addr", cfg.Addr, "app_env", cfg.AppEnv)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
	}
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	return nil
}
