package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/linlay/zenmind-official-server/internal/auth"
	"github.com/linlay/zenmind-official-server/internal/config"
	"github.com/linlay/zenmind-official-server/internal/release"
)

func main() {
	if err := run(); err != nil {
		log.Printf("server stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := auth.OpenMySQL(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := store.EnsureSchema(ctx); err != nil {
		return err
	}
	if err := auth.EnsureInitialAdmin(ctx, store, cfg.InitAdminEmail, cfg.InitAdminPassword); err != nil {
		return err
	}

	if cfg.SQLiteDBPathLegacy {
		log.Printf("Using legacy SQLite database path %s. Set SQLITE_DB_PATH=/data/data.sqlite after migrating the existing database file.", cfg.SQLiteDBPath)
	}

	installerCatalog, err := release.OpenSQLite(ctx, cfg.SQLiteDBPath)
	if err != nil {
		return err
	}
	defer installerCatalog.Close()
	if err := installerCatalog.EnsureSchema(ctx); err != nil {
		return err
	}

	downloadStore, err := auth.OpenSQLiteDownloadStore(ctx, cfg.SQLiteDBPath)
	if err != nil {
		return err
	}
	defer downloadStore.Close()
	if err := downloadStore.EnsureSchema(ctx); err != nil {
		return err
	}

	app := auth.NewServer(store, auth.ServerOptions{
		CookieName:   cfg.CookieName,
		CookieSecure: cfg.CookieSecure,
		SessionTTL:   cfg.SessionTTL,
		Google: auth.NewGoogleProvider(auth.GoogleProviderConfig{
			ClientID:        cfg.GoogleClientID,
			ClientSecret:    cfg.GoogleSecret,
			RedirectURL:     cfg.GoogleRedirectURL,
			DesktopClientID: cfg.GoogleDesktopID,
		}),
		AuthSuccessURL:   cfg.AuthSuccessURL,
		AuthFailureURL:   cfg.AuthFailureURL,
		MarketServerURL:  cfg.MarketServerURL,
		MarketProxyToken: cfg.MarketProxyToken,
		InstallerCatalog: installerCatalog,
		DownloadStore:    downloadStore,
		Mailer: auth.NewSMTPMailer(auth.SMTPMailerConfig{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUsername,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
		}),
	})
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("ZenMind API listening on %s", cfg.Addr)
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
