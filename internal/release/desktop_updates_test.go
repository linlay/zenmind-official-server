package release

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testDesktopManifest() DesktopManifest {
	return DesktopManifest{SchemaVersion: 1, ProductID: "cutej", Version: "0.5.0", PublishedAt: "2026-09-12T08:00:00Z", ReleaseNotes: map[string][]string{"zh-CN": {"更新说明"}, "en-US": {"Update notes"}}, Artifacts: map[string]DesktopArtifact{
		"darwin-arm64": {URL: "https://example.com/CuteJ-0.5.0.zip", Size: 123, SHA256: strings.Repeat("a", 64)},
		"win32-x64":    {URL: "https://example.com/CuteJ-0.5.0.exe", Size: 456, SHA256: strings.Repeat("b", 64)},
	}}
}

func TestDesktopUpdateValidation(t *testing.T) {
	mutations := map[string]func(*DesktopManifest){
		"schema":          func(m *DesktopManifest) { m.SchemaVersion = 2 },
		"product":         func(m *DesktopManifest) { m.ProductID = "../cutej" },
		"prerelease":      func(m *DesktopManifest) { m.Version = "0.5.0-beta.01" },
		"leading zero":    func(m *DesktopManifest) { m.Version = "0.05.0" },
		"date":            func(m *DesktopManifest) { m.PublishedAt = "yesterday" },
		"notes":           func(m *DesktopManifest) { m.ReleaseNotes = nil },
		"empty artifacts": func(m *DesktopManifest) { m.Artifacts = map[string]DesktopArtifact{} },
		"unknown arch":    func(m *DesktopManifest) { m.Artifacts["linux-x64"] = m.Artifacts["darwin-arm64"] },
		"http": func(m *DesktopManifest) {
			a := m.Artifacts["darwin-arm64"]
			a.URL = "http://example.com/app.zip"
			m.Artifacts["darwin-arm64"] = a
		},
		"credentials": func(m *DesktopManifest) {
			a := m.Artifacts["darwin-arm64"]
			a.URL = "https://user:secret@example.com/app.zip"
			m.Artifacts["darwin-arm64"] = a
		},
		"dmg": func(m *DesktopManifest) {
			a := m.Artifacts["darwin-arm64"]
			a.URL = "https://example.com/app.dmg"
			m.Artifacts["darwin-arm64"] = a
		},
		"size": func(m *DesktopManifest) {
			a := m.Artifacts["darwin-arm64"]
			a.Size = 0
			m.Artifacts["darwin-arm64"] = a
		},
		"hash": func(m *DesktopManifest) {
			a := m.Artifacts["darwin-arm64"]
			a.SHA256 = "bad"
			m.Artifacts["darwin-arm64"] = a
		},
		"too large": func(m *DesktopManifest) {
			for _, lang := range []string{"zh-CN", "en-US", "fr-FR"} {
				m.ReleaseNotes[lang] = make([]string, 100)
				for i := range m.ReleaseNotes[lang] {
					m.ReleaseNotes[lang][i] = strings.Repeat("x", 2000)
				}
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m := testDesktopManifest()
			mutate(&m)
			if err := ValidateDesktopManifest(m); !errors.Is(err, ErrInvalidDesktopUpdate) {
				t.Fatalf("invalid manifest accepted: %v", err)
			}
		})
	}
}

func TestDesktopUpdateMatchesRendererStringAndURLLimits(t *testing.T) {
	m := testDesktopManifest()
	m.ReleaseNotes["en-US"] = []string{strings.Repeat("😀", 1001)}
	if err := ValidateDesktopManifest(m); !errors.Is(err, ErrInvalidDesktopUpdate) {
		t.Fatal("accepted notes beyond Desktop UTF-16 length limit", err)
	}
	m = testDesktopManifest()
	a := m.Artifacts["darwin-arm64"]
	a.URL = "https://example.com/app%2Ezip"
	m.Artifacts["darwin-arm64"] = a
	if err := ValidateDesktopManifest(m); !errors.Is(err, ErrInvalidDesktopUpdate) {
		t.Fatal("accepted extension not recognized by Desktop", err)
	}
}

func feedInput(m DesktopManifest, revision int64, enabled bool) UpdateFeedInput {
	return UpdateFeedInput{Description: "Test", Manifest: m, Revision: revision, Enabled: &enabled}
}
func openFeedStore(t *testing.T) *SQLiteCatalog {
	t.Helper()
	c, err := OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "site.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}
func TestNamedFeedsIndependentHistoryConflictAndDisable(t *testing.T) {
	ctx := context.Background()
	c := openFeedStore(t)
	if items, err := c.ListUpdateFeeds(ctx); err != nil || len(items) != 0 {
		t.Fatal(items, err)
	}
	stable := testDesktopManifest()
	beta := testDesktopManifest()
	beta.Version = "0.6.0-beta.1"
	if _, err := c.SaveUpdateFeed(ctx, "desktop-latest.json", feedInput(stable, 0, true), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SaveUpdateFeed(ctx, "desktop-beta.json", feedInput(beta, 0, true), 2); err != nil {
		t.Fatal(err)
	}
	if got, err := c.GetPublicUpdate(ctx, "desktop-latest.json"); err != nil || !reflect.DeepEqual(got, stable) {
		t.Fatal(got, err)
	}
	if got, err := c.GetPublicUpdate(ctx, "desktop-beta.json"); err != nil || !reflect.DeepEqual(got, beta) {
		t.Fatal(got, err)
	}
	if _, err := c.SaveUpdateFeed(ctx, "desktop-latest.json", feedInput(stable, 0, true), 1); !errors.Is(err, ErrUpdateConflict) {
		t.Fatal("duplicate create", err)
	}
	if _, err := c.SaveUpdateFeed(ctx, "desktop-beta.json", feedInput(beta, 1, false), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPublicUpdate(ctx, "desktop-beta.json"); !errors.Is(err, ErrDesktopUpdateNotFound) {
		t.Fatal("disabled is public", err)
	}
	if _, err := c.SaveUpdateFeed(ctx, "desktop-beta.json", feedInput(beta, 1, true), 1); !errors.Is(err, ErrUpdateConflict) {
		t.Fatal("stale write", err)
	}
	history, err := c.UpdateFeedHistory(ctx, "desktop-beta.json")
	if err != nil || len(history) != 2 || history[0].Enabled || history[1].Revision != 1 {
		t.Fatal(history, err)
	}
	if _, err := c.SaveUpdateFeed(ctx, "desktop-beta.json", feedInput(*history[1].Manifest, 2, true), 1); err != nil {
		t.Fatal(err)
	}
	if item, err := c.GetUpdateFeed(ctx, "desktop-beta.json"); err != nil || item.Revision != 3 || item.UpdatedBy != 1 {
		t.Fatal(item, err)
	}
	for _, name := range []string{"../desktop.json", "nested/a.json", "desktop.JSON", "desktop.json?x=1", "a..json", "/etc/passwd"} {
		if _, err := c.SaveUpdateFeed(ctx, name, feedInput(stable, 0, true), 1); !errors.Is(err, ErrInvalidDesktopUpdate) {
			t.Fatal(name, err)
		}
	}
}
func TestFeedWriteRollbackAndReadValidation(t *testing.T) {
	ctx := context.Background()
	c := openFeedStore(t)
	m := testDesktopManifest()
	if _, err := c.SaveUpdateFeed(ctx, "desktop-latest.json", feedInput(m, 0, true), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.ExecContext(ctx, `CREATE TRIGGER fail_switch BEFORE UPDATE ON update_feed BEGIN SELECT RAISE(ABORT,'failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SaveUpdateFeed(ctx, "desktop-latest.json", feedInput(m, 1, false), 1); err == nil {
		t.Fatal("switch should fail")
	}
	h, err := c.UpdateFeedHistory(ctx, "desktop-latest.json")
	if err != nil || len(h) != 1 {
		t.Fatal(h, err)
	}
	if _, err := c.db.ExecContext(ctx, `UPDATE update_feed_revision SET MANIFEST_='null'`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPublicUpdate(ctx, "desktop-latest.json"); !errors.Is(err, ErrInvalidDesktopUpdate) {
		t.Fatal("corrupt manifest accepted", err)
	}
}
func TestLegacySingletonMigratesOnce(t *testing.T) {
	ctx := context.Background()
	c, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "site.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, stmt := range []string{`CREATE TABLE desktop_update_release(ID_ INTEGER PRIMARY KEY,MANIFEST_ TEXT,CREATED_AT_ TEXT)`, `CREATE TABLE desktop_update_current(ID_ INTEGER PRIMARY KEY,RELEASE_ID_ INTEGER)`} {
		if _, err := c.db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(testDesktopManifest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.ExecContext(ctx, `INSERT INTO desktop_update_release VALUES(1,?,'2026-09-12T08:00:00Z')`, string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.ExecContext(ctx, `INSERT INTO desktop_update_current VALUES(1,1)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := c.EnsureSchema(ctx); err != nil {
			t.Fatal(err)
		}
	}
	item, err := c.GetUpdateFeed(ctx, "desktop-latest.json")
	if err != nil || item.Revision != 1 || !item.Enabled {
		t.Fatal(item, err)
	}
	if _, err := c.SaveUpdateFeed(ctx, item.Name, feedInput(*item.Manifest, 1, false), 2); err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPublicUpdate(ctx, item.Name); !errors.Is(err, ErrDesktopUpdateNotFound) {
		t.Fatal("migration overwrote disabled state", err)
	}
}

func TestDesktopManifestAcceptsPrerelease(t *testing.T) {
	m := testDesktopManifest()
	m.Version = "0.6.0-dev.1"
	if err := ValidateDesktopManifest(m); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFeedManifest(string(raw))
	if err != nil || !reflect.DeepEqual(decoded, m) {
		t.Fatal(decoded, err)
	}
}
