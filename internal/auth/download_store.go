package auth

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type DownloadStore interface {
	EnsureSchema(ctx context.Context) error
	ListDownloadStats(ctx context.Context) ([]DownloadStat, error)
	RecordDownloadEvent(ctx context.Context, event DownloadEvent) error
}

type SQLiteDownloadStore struct {
	db *sql.DB
}

func OpenSQLiteDownloadStore(ctx context.Context, dbPath string) (*SQLiteDownloadStore, error) {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return nil, fmt.Errorf("sqlite download store: database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	for _, statement := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			db.Close()
			return nil, err
		}
	}

	return &SQLiteDownloadStore{db: db}, nil
}

func (s *SQLiteDownloadStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteDownloadStore) EnsureSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS download_stat (
			INSTALLER_KEY_ TEXT NOT NULL PRIMARY KEY,
			TOTAL_ INTEGER NOT NULL DEFAULT 0,
			CREATED_AT_ TEXT NOT NULL,
			UPDATED_AT_ TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS download (
			ID_ INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			INSTALLER_KEY_ TEXT NOT NULL,
			VERSION_ TEXT NOT NULL DEFAULT '',
			CLIENT_IP_ TEXT NOT NULL DEFAULT '',
			REMOTE_ADDR_ TEXT NOT NULL DEFAULT '',
			X_FORWARDED_FOR_ TEXT NOT NULL DEFAULT '',
			X_REAL_IP_ TEXT NOT NULL DEFAULT '',
			USER_AGENT_ TEXT NOT NULL DEFAULT '',
			REFERER_ TEXT NOT NULL DEFAULT '',
			ACCEPT_LANGUAGE_ TEXT NOT NULL DEFAULT '',
			DOWNLOADED_AT_ TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS IDX_DOWNLOAD_INSTALLER_AT ON download (INSTALLER_KEY_, DOWNLOADED_AT_)`,
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteDownloadStore) ListDownloadStats(ctx context.Context) ([]DownloadStat, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT INSTALLER_KEY_, TOTAL_ FROM download_stat`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []DownloadStat
	for rows.Next() {
		var stat DownloadStat
		if err := rows.Scan(&stat.InstallerKey, &stat.Total); err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	return stats, rows.Err()
}

func (s *SQLiteDownloadStore) RecordDownloadEvent(ctx context.Context, event DownloadEvent) error {
	now := time.Now().UTC()
	if event.DownloadedAt.IsZero() {
		event.DownloadedAt = now
	}
	downloadedAt := event.DownloadedAt.UTC().Format(time.RFC3339Nano)
	updatedAt := now.Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	installerKey := truncate(strings.TrimSpace(event.InstallerKey), 64)
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO download (
			INSTALLER_KEY_,
			VERSION_,
			CLIENT_IP_,
			REMOTE_ADDR_,
			X_FORWARDED_FOR_,
			X_REAL_IP_,
			USER_AGENT_,
			REFERER_,
			ACCEPT_LANGUAGE_,
			DOWNLOADED_AT_
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		installerKey,
		truncate(strings.TrimSpace(event.Version), 32),
		truncate(strings.TrimSpace(event.ClientIP), 64),
		truncate(strings.TrimSpace(event.RemoteAddr), 128),
		truncate(strings.TrimSpace(event.XForwardedFor), 1024),
		truncate(strings.TrimSpace(event.XRealIP), 64),
		truncate(strings.TrimSpace(event.UserAgent), 512),
		truncate(strings.TrimSpace(event.Referer), 1024),
		truncate(strings.TrimSpace(event.AcceptLanguage), 256),
		downloadedAt,
	); err != nil {
		return err
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO download_stat (INSTALLER_KEY_, TOTAL_, CREATED_AT_, UPDATED_AT_)
		 VALUES (?, 1, ?, ?)
		 ON CONFLICT(INSTALLER_KEY_) DO UPDATE SET
			TOTAL_ = TOTAL_ + 1,
			UPDATED_AT_ = excluded.UPDATED_AT_`,
		installerKey,
		updatedAt,
		updatedAt,
	); err != nil {
		return err
	}

	return tx.Commit()
}

type disabledDownloadStore struct{}

func (disabledDownloadStore) EnsureSchema(context.Context) error {
	return nil
}

func (disabledDownloadStore) ListDownloadStats(context.Context) ([]DownloadStat, error) {
	return nil, nil
}

func (disabledDownloadStore) RecordDownloadEvent(context.Context, DownloadEvent) error {
	return nil
}
