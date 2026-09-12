package release

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

var ErrUpdateConflict = errors.New("update feed changed; reload before saving")
var feedNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,79}\.json$`)

func ValidUpdateName(name string) bool { return feedNamePattern.MatchString(name) }

type UpdateFeed struct {
	ETag        string           `json:"etag,omitempty"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Enabled     bool             `json:"enabled"`
	Revision    int64            `json:"revision"`
	UpdatedAt   string           `json:"updatedAt"`
	UpdatedBy   int64            `json:"updatedBy"`
	Manifest    *DesktopManifest `json:"manifest,omitempty"`
}
type UpdateFeedInput struct {
	ETag        string          `json:"etag,omitempty"`
	Description string          `json:"description"`
	Enabled     *bool           `json:"enabled"`
	Revision    int64           `json:"revision"`
	Manifest    DesktopManifest `json:"manifest"`
}
type DesktopUpdateCatalog interface {
	GetPublicUpdate(context.Context, string) (DesktopManifest, error)
	ListUpdateFeeds(context.Context) ([]UpdateFeed, error)
	GetUpdateFeed(context.Context, string) (UpdateFeed, error)
	UpdateFeedHistory(context.Context, string) ([]UpdateFeed, error)
	SaveUpdateFeed(context.Context, string, UpdateFeedInput, int64) (UpdateFeed, error)
}

func (c *SQLiteCatalog) ensureDesktopUpdateSchema(ctx context.Context) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS update_feed (NAME_ TEXT PRIMARY KEY, REVISION_ INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS update_feed_revision (NAME_ TEXT NOT NULL, REVISION_ INTEGER NOT NULL, DESCRIPTION_ TEXT NOT NULL, ENABLED_ INTEGER NOT NULL, MANIFEST_ TEXT NOT NULL, UPDATED_AT_ TEXT NOT NULL, UPDATED_BY_ INTEGER NOT NULL, PRIMARY KEY(NAME_, REVISION_))`,
		`CREATE TABLE IF NOT EXISTS update_feed_migration (ID_ INTEGER PRIMARY KEY CHECK(ID_=1))`,
	} {
		if _, err = tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	var migrated int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM update_feed_migration`).Scan(&migrated); err != nil {
		return err
	}
	if migrated == 0 {
		var legacy int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='desktop_update_current'`).Scan(&legacy); err != nil {
			return err
		}
		if legacy > 0 {
			// Preserve the original singleton under its existing public name, including history.
			// Keep legacy tables as a read-only migration source; never re-import on startup.
			if _, err = tx.ExecContext(ctx, `INSERT INTO update_feed_revision SELECT 'desktop-latest.json', ID_, '', 1, MANIFEST_, CREATED_AT_, 0 FROM desktop_update_release`); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO update_feed SELECT 'desktop-latest.json', RELEASE_ID_ FROM desktop_update_current WHERE ID_=1`); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO update_feed_migration VALUES (1)`); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func decodeFeedManifest(data string) (DesktopManifest, error) {
	var m DesktopManifest
	if len(data) > MaxDesktopManifestBytes {
		return m, ErrInvalidDesktopUpdate
	}
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return m, ErrInvalidDesktopUpdate
	}
	if err := ValidateDesktopManifest(m); err != nil {
		return DesktopManifest{}, err
	}
	return m, nil
}
func scanFeed(row interface{ Scan(...any) error }, withManifest bool) (UpdateFeed, error) {
	var item UpdateFeed
	var data string
	targets := []any{&item.Name, &item.Description, &item.Enabled, &item.Revision, &item.UpdatedAt, &item.UpdatedBy}
	if withManifest {
		targets = append(targets, &data)
	}
	if err := row.Scan(targets...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return item, ErrDesktopUpdateNotFound
		}
		return item, err
	}
	if withManifest {
		m, err := decodeFeedManifest(data)
		if err != nil {
			return item, err
		}
		item.Manifest = &m
	}
	return item, nil
}

const feedColumns = `r.NAME_, r.DESCRIPTION_, r.ENABLED_, r.REVISION_, r.UPDATED_AT_, r.UPDATED_BY_`

func (c *SQLiteCatalog) ListUpdateFeeds(ctx context.Context) ([]UpdateFeed, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT `+feedColumns+` FROM update_feed f JOIN update_feed_revision r ON f.NAME_=r.NAME_ AND f.REVISION_=r.REVISION_ ORDER BY r.NAME_`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []UpdateFeed{}
	for rows.Next() {
		item, err := scanFeed(rows, false)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (c *SQLiteCatalog) GetUpdateFeed(ctx context.Context, name string) (UpdateFeed, error) {
	if !ValidUpdateName(name) {
		return UpdateFeed{}, ErrDesktopUpdateNotFound
	}
	return scanFeed(c.db.QueryRowContext(ctx, `SELECT `+feedColumns+`,r.MANIFEST_ FROM update_feed f LEFT JOIN update_feed_revision r ON f.NAME_=r.NAME_ AND f.REVISION_=r.REVISION_ WHERE f.NAME_=?`, name), true)
}
func (c *SQLiteCatalog) GetPublicUpdate(ctx context.Context, name string) (DesktopManifest, error) {
	// A disabled record is 404 regardless of the validity of its unpublished content.
	if !ValidUpdateName(name) {
		return DesktopManifest{}, ErrDesktopUpdateNotFound
	}
	var enabled bool
	var data string
	err := c.db.QueryRowContext(ctx, `SELECT r.ENABLED_,r.MANIFEST_ FROM update_feed f LEFT JOIN update_feed_revision r ON f.NAME_=r.NAME_ AND f.REVISION_=r.REVISION_ WHERE f.NAME_=?`, name).Scan(&enabled, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return DesktopManifest{}, ErrDesktopUpdateNotFound
	}
	if err != nil {
		return DesktopManifest{}, err
	}
	if !enabled {
		return DesktopManifest{}, ErrDesktopUpdateNotFound
	}
	return decodeFeedManifest(data)
}
func (c *SQLiteCatalog) UpdateFeedHistory(ctx context.Context, name string) ([]UpdateFeed, error) {
	if _, err := c.GetUpdateFeed(ctx, name); err != nil {
		return nil, err
	}
	rows, err := c.db.QueryContext(ctx, `SELECT `+feedColumns+`,r.MANIFEST_ FROM update_feed_revision r WHERE r.NAME_=? ORDER BY r.REVISION_ DESC LIMIT 20`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []UpdateFeed{}
	for rows.Next() {
		item, err := scanFeed(rows, true)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (c *SQLiteCatalog) SaveUpdateFeed(ctx context.Context, name string, input UpdateFeedInput, actor int64) (UpdateFeed, error) {
	if !ValidUpdateName(name) || input.Enabled == nil || input.Revision < 0 || actor <= 0 || utf8.RuneCountInString(input.Description) > 500 {
		return UpdateFeed{}, fmt.Errorf("%w: name, description, revision or enabled", ErrInvalidDesktopUpdate)
	}
	if err := ValidateDesktopManifest(input.Manifest); err != nil {
		return UpdateFeed{}, err
	}
	data, err := json.Marshal(input.Manifest)
	if err != nil {
		return UpdateFeed{}, err
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return UpdateFeed{}, err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT REVISION_ FROM update_feed WHERE NAME_=?`, name).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return UpdateFeed{}, err
	}
	if current != input.Revision {
		return UpdateFeed{}, ErrUpdateConflict
	}
	var next int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(REVISION_),0)+1 FROM update_feed_revision WHERE NAME_=?`, name).Scan(&next); err != nil {
		return UpdateFeed{}, err
	}
	item := UpdateFeed{Name: name, Description: input.Description, Enabled: *input.Enabled, Revision: next, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), UpdatedBy: actor, Manifest: &input.Manifest}
	_, err = tx.ExecContext(ctx, `INSERT INTO update_feed_revision VALUES(?,?,?,?,?,?,?)`, name, next, input.Description, *input.Enabled, string(data), item.UpdatedAt, actor)
	if err != nil {
		return UpdateFeed{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO update_feed VALUES(?,?) ON CONFLICT(NAME_) DO UPDATE SET REVISION_=excluded.REVISION_`, name, next)
	if err != nil {
		return UpdateFeed{}, err
	}
	if err = tx.Commit(); err != nil {
		return UpdateFeed{}, err
	}
	return item, nil
}
