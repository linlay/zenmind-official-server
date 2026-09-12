package release

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryUpdatesManualPublishAndAdmin(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c, err := OpenDirectoryUpdates(ctx, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, _ := json.Marshal(testDesktopManifest())
	name := "desktop-beta.json"
	if err = os.WriteFile(filepath.Join(dir, name), raw, 0644); err != nil {
		t.Fatal(err)
	}
	got, err := c.GetPublicJSON(ctx, name)
	if err != nil || string(got) != string(raw) {
		t.Fatal(string(got), err)
	}
	item, err := c.GetUpdateFeed(ctx, name)
	if err != nil || !item.Enabled || item.ETag == "" {
		t.Fatal(item, err)
	}
	items, err := c.ListUpdateFeeds(ctx)
	if err != nil || len(items) != 1 {
		t.Fatal(items, err)
	}
	changed := testDesktopManifest()
	changed.Version = "0.5.1"
	next, _ := json.Marshal(changed)
	os.WriteFile(filepath.Join(dir, name), next, 0644)
	input := feedInput(testDesktopManifest(), item.Revision, false)
	input.ETag = item.ETag
	if _, err = c.SaveUpdateFeed(ctx, name, input, 1); !errors.Is(err, ErrUpdateConflict) {
		t.Fatal("manual replacement did not invalidate editor", err)
	}
	item, _ = c.GetUpdateFeed(ctx, name)
	input.ETag = item.ETag
	saved, err := c.SaveUpdateFeed(ctx, name, input, 1)
	if err != nil || saved.Enabled {
		t.Fatal(saved, err)
	}
	if _, err = c.GetPublicJSON(ctx, name); !errors.Is(err, ErrDesktopUpdateNotFound) {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, ".disabled", name)); err != nil {
		t.Fatal(err)
	}
	input = feedInput(testDesktopManifest(), saved.Revision, true)
	input.ETag = saved.ETag
	saved, err = c.SaveUpdateFeed(ctx, name, input, 1)
	if err != nil || !saved.Enabled {
		t.Fatal(saved, err)
	}
	history, err := c.UpdateFeedHistory(ctx, name)
	if err != nil || len(history) != 2 {
		t.Fatal(history, err)
	}
	os.Remove(filepath.Join(dir, name))
	if _, err = c.GetPublicJSON(ctx, name); !errors.Is(err, ErrDesktopUpdateNotFound) {
		t.Fatal("metadata resurrected removed file", err)
	}
	// Public JSON is independent from both Desktop schema and Admin sidecars.
	os.WriteFile(filepath.Join(dir, "custom.json"), []byte(`{"future":true}`), 0644)
	if got, err = c.GetPublicJSON(ctx, "custom.json"); err != nil || string(got) != `{"future":true}` {
		t.Fatal(string(got), err)
	}
	os.WriteFile(filepath.Join(dir, "broken.json"), []byte(`{`), 0644)
	if _, err = c.GetPublicJSON(ctx, "broken.json"); err == nil {
		t.Fatal("invalid JSON exposed")
	}
	outside := filepath.Join(t.TempDir(), "secret.json")
	os.WriteFile(outside, raw, 0644)
	os.Symlink(outside, filepath.Join(dir, "link.json"))
	for _, name := range []string{"../secret.json", ".admin/desktop-beta.json", "link.json"} {
		if _, err = c.GetPublicJSON(ctx, name); err == nil {
			t.Fatal("unsafe path", name)
		}
	}
}
func TestDirectoryExportPreservesLegacyAndDoesNotResurrect(t *testing.T) {
	ctx := context.Background()
	legacy := openFeedStore(t)
	m := testDesktopManifest()
	item, err := legacy.SaveUpdateFeed(ctx, "desktop-latest.json", feedInput(m, 0, true), 1)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	c, err := OpenDirectoryUpdates(ctx, dir, legacy)
	if err != nil {
		t.Fatal(err)
	}
	history, err := c.UpdateFeedHistory(ctx, item.Name)
	if err != nil || len(history) != 1 || history[0].Description != "Test" {
		t.Fatal(history, err)
	}
	if _, err = c.GetPublicJSON(ctx, item.Name); err != nil {
		t.Fatal(err)
	}
	c.Close()
	os.Remove(filepath.Join(dir, item.Name))
	c, err = OpenDirectoryUpdates(ctx, dir, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.GetPublicJSON(ctx, item.Name); !errors.Is(err, ErrDesktopUpdateNotFound) {
		t.Fatal("re-export resurrected file", err)
	}
	if _, err = legacy.GetUpdateFeed(ctx, item.Name); err != nil {
		t.Fatal("legacy data lost", err)
	}
	dir2 := t.TempDir()
	os.WriteFile(filepath.Join(dir2, item.Name), []byte(`{"existing":true}`), 0644)
	second, err := OpenDirectoryUpdates(ctx, dir2, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got, err := second.GetPublicJSON(ctx, item.Name); err != nil || string(got) != `{"existing":true}` {
		t.Fatal("existing file overwritten", string(got), err)
	}
}
