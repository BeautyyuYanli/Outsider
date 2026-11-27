package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"outsider/internal/relay/config"
	"outsider/internal/relay/notifier"
	"outsider/internal/relay/server"
	"outsider/internal/relay/session"
)

var version = "0.1.0"

func main() {
	defaultCfg := os.Getenv("OUTSIDER_RELAY_CONFIG")
	if defaultCfg == "" {
		defaultCfg = "relay.toml"
	}

	configPath := flag.String("config", defaultCfg, "path to relay.toml configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("outsider-relay %s\n", version)
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		logger.Error("failed to load config", "path", *configPath, "error", err)
		os.Exit(1)
	}
	notif, err := notifier.BuildFromConfig(cfg.Notifiers, logger)
	if err != nil {
		logger.Error("failed to initialize notifiers", "error", err)
		os.Exit(1)
	}

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	store := session.NewStore()
	store.StartReaper(rootCtx, 5*time.Second)

	srv := server.New(cfg, store, notif, logger)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// SIGHUP hot-reloads relay.toml (trusted_clients, notifiers, limits) without dropping active sessions.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-sighupCh:
				newCfg, err := config.LoadFile(*configPath)
				if err != nil {
					logger.Error("SIGHUP reload failed; keeping previous config", "error", err)
					continue
				}
				newNotif, err := notifier.BuildFromConfig(newCfg.Notifiers, logger)
				if err != nil {
					logger.Error("SIGHUP notifier rebuild failed; keeping previous config", "error", err)
					continue
				}
				srv.UpdateConfig(newCfg, newNotif)
				logger.Info("reloaded relay.toml",
					"trusted_clients", len(newCfg.TrustedClients),
					"notifiers", len(newCfg.Notifiers),
				)
			}
		}
	}()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("outsider-relay listening",
			"addr", cfg.ListenAddr,
			"public_base_url", cfg.PublicBaseURL,
			"trusted_clients", len(cfg.TrustedClients),
			"notifiers", len(cfg.Notifiers),
		)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case sig := <-stopCh:
		logger.Info("shutting down", "signal", sig.String())
		rootCancel()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown error", "error", err)
			os.Exit(1)
		}
	case err := <-errCh:
		if err != nil {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}
}
