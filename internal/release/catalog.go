package release

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	PublicDownloadBase = "/install/releases/desktop"
)

var (
	ErrInvalidInstallerKey = errors.New("invalid installer key")
	ErrInvalidInstaller    = errors.New("invalid installer")
)

var allowedInstallerKeys = map[string]bool{
	"mac":     true,
	"windows": true,
}

type Installer struct {
	Key       string    `json:"key"`
	Available bool      `json:"available"`
	Version   string    `json:"version"`
	Href      string    `json:"href"`
	FileName  string    `json:"fileName"`
	SizeBytes int64     `json:"sizeBytes"`
	SHA256    string    `json:"sha256"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Catalog interface {
	ListInstallers(ctx context.Context) ([]Installer, error)
}

type SQLiteCatalog struct {
	db *sql.DB
}

func IsAllowedInstallerKey(key string) bool {
	return allowedInstallerKeys[strings.TrimSpace(key)]
}

func NewInstallerHref(version, fileName string) string {
	return path.Join(PublicDownloadBase, strings.TrimSpace(version), strings.TrimSpace(fileName))
}

func OpenSQLite(ctx context.Context, dbPath string) (*SQLiteCatalog, error) {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return nil, fmt.Errorf("%w: database path is required", ErrInvalidInstaller)
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

	return &SQLiteCatalog{db: db}, nil
}

func (c *SQLiteCatalog) Close() error {
	return c.db.Close()
}

func (c *SQLiteCatalog) EnsureSchema(ctx context.Context) error {
	_, err := c.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS installer (
		KEY_ TEXT NOT NULL PRIMARY KEY,
		AVAILABLE_ INTEGER NOT NULL DEFAULT 1,
		VERSION_ TEXT NOT NULL DEFAULT '',
		HREF_ TEXT NOT NULL DEFAULT '',
		FILE_NAME_ TEXT NOT NULL DEFAULT '',
		SIZE_BYTES_ INTEGER NOT NULL DEFAULT 0,
		SHA256_ TEXT NOT NULL DEFAULT '',
		CREATED_AT_ TEXT NOT NULL,
		UPDATED_AT_ TEXT NOT NULL
	)`)
	return err
}

func (c *SQLiteCatalog) ListInstallers(ctx context.Context) ([]Installer, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT KEY_, AVAILABLE_, VERSION_, HREF_, FILE_NAME_, SIZE_BYTES_, SHA256_, UPDATED_AT_
		FROM installer
		WHERE KEY_ IN ('windows', 'mac')
		ORDER BY CASE KEY_ WHEN 'windows' THEN 1 WHEN 'mac' THEN 2 ELSE 99 END`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var installers []Installer
	for rows.Next() {
		var installer Installer
		var available int
		var updatedAt string
		if err := rows.Scan(
			&installer.Key,
			&available,
			&installer.Version,
			&installer.Href,
			&installer.FileName,
			&installer.SizeBytes,
			&installer.SHA256,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		if !IsAllowedInstallerKey(installer.Key) {
			continue
		}
		installer.Available = available == 1
		parsedUpdatedAt, err := time.Parse(time.RFC3339Nano, updatedAt)
		if err != nil {
			return nil, err
		}
		installer.UpdatedAt = parsedUpdatedAt
		installers = append(installers, installer)
	}
	return installers, rows.Err()
}

func (c *SQLiteCatalog) UpsertInstaller(ctx context.Context, installer Installer) error {
	installer.Key = strings.TrimSpace(installer.Key)
	installer.Version = strings.TrimSpace(installer.Version)
	installer.Href = strings.TrimSpace(installer.Href)
	installer.FileName = strings.TrimSpace(installer.FileName)
	installer.SHA256 = strings.TrimSpace(installer.SHA256)

	if !IsAllowedInstallerKey(installer.Key) {
		return ErrInvalidInstallerKey
	}
	if installer.Available {
		if installer.Version == "" || installer.Href == "" || installer.FileName == "" {
			return fmt.Errorf("%w: version, href, and filename are required", ErrInvalidInstaller)
		}
		if installer.SizeBytes < 0 {
			return fmt.Errorf("%w: size must be non-negative", ErrInvalidInstaller)
		}
		if !strings.HasPrefix(installer.Href, PublicDownloadBase+"/") {
			return fmt.Errorf("%w: href must live under %s", ErrInvalidInstaller, PublicDownloadBase)
		}
	}

	now := time.Now().UTC()
	if installer.UpdatedAt.IsZero() {
		installer.UpdatedAt = now
	}
	createdAt := now.Format(time.RFC3339Nano)
	updatedAt := installer.UpdatedAt.UTC().Format(time.RFC3339Nano)
	available := 0
	if installer.Available {
		available = 1
	}

	_, err := c.db.ExecContext(
		ctx,
		`INSERT INTO installer (KEY_, AVAILABLE_, VERSION_, HREF_, FILE_NAME_, SIZE_BYTES_, SHA256_, CREATED_AT_, UPDATED_AT_)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(KEY_) DO UPDATE SET
			AVAILABLE_ = excluded.AVAILABLE_,
			VERSION_ = excluded.VERSION_,
			HREF_ = excluded.HREF_,
			FILE_NAME_ = excluded.FILE_NAME_,
			SIZE_BYTES_ = excluded.SIZE_BYTES_,
			SHA256_ = excluded.SHA256_,
			UPDATED_AT_ = excluded.UPDATED_AT_`,
		installer.Key,
		available,
		installer.Version,
		installer.Href,
		installer.FileName,
		installer.SizeBytes,
		installer.SHA256,
		createdAt,
		updatedAt,
	)
	return err
}
