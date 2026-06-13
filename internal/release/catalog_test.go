package release

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteCatalogUpsertListAndRejectsInvalidKey(t *testing.T) {
	ctx := context.Background()
	catalog, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "installers.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer catalog.Close()
	if err := catalog.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}

	err = catalog.UpsertInstaller(ctx, Installer{Key: "linux", Available: true})
	if !errors.Is(err, ErrInvalidInstallerKey) {
		t.Fatalf("expected invalid key, got %v", err)
	}

	updatedAt := time.Date(2026, 6, 13, 1, 2, 3, 0, time.UTC)
	err = catalog.UpsertInstaller(ctx, Installer{
		Key:       "windows",
		Available: true,
		Version:   "0.2.4",
		Href:      "/install/releases/desktop/0.2.4/ZenMind-0.2.4-x64.exe",
		FileName:  "ZenMind-0.2.4-x64.exe",
		SizeBytes: 12,
		SHA256:    "abc123",
		UpdatedAt: updatedAt,
	})
	if err != nil {
		t.Fatalf("upsert installer: %v", err)
	}

	installers, err := catalog.ListInstallers(ctx)
	if err != nil {
		t.Fatalf("list installers: %v", err)
	}
	if len(installers) != 1 {
		t.Fatalf("expected one installer, got %#v", installers)
	}
	got := installers[0]
	if got.Key != "windows" || !got.Available || got.Version != "0.2.4" || got.FileName != "ZenMind-0.2.4-x64.exe" {
		t.Fatalf("unexpected installer: %#v", got)
	}
	if got.SizeBytes != 12 || got.SHA256 != "abc123" || !got.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("unexpected metadata: %#v", got)
	}
}
