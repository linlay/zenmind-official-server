package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUpsertFileCopiesInstallerAndWritesCatalog(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "source.exe")
	sourceContent := []byte("windows-installer")
	if err := os.WriteFile(sourcePath, sourceContent, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	installer, err := UpsertFile(ctx, UpsertFileOptions{
		DBPath:      filepath.Join(tempDir, "installers.sqlite"),
		ReleaseRoot: filepath.Join(tempDir, "releases"),
		Key:         "windows",
		Version:     "0.2.4",
		Source:      sourcePath,
		FileName:    "ZenMind-0.2.4-x64.exe",
	})
	if err != nil {
		t.Fatalf("upsert file: %v", err)
	}

	targetPath := filepath.Join(tempDir, "releases", "desktop", "0.2.4", "ZenMind-0.2.4-x64.exe")
	targetContent, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(targetContent) != string(sourceContent) {
		t.Fatalf("target content = %q", targetContent)
	}

	hash := sha256.Sum256(sourceContent)
	expectedSHA := hex.EncodeToString(hash[:])
	if installer.Href != "/install/releases/desktop/0.2.4/ZenMind-0.2.4-x64.exe" {
		t.Fatalf("unexpected href %q", installer.Href)
	}
	if installer.SizeBytes != int64(len(sourceContent)) || installer.SHA256 != expectedSHA {
		t.Fatalf("unexpected metadata: %#v", installer)
	}
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if targetInfo.Mode().Perm() != 0o644 {
		t.Fatalf("target mode = %o, want 644", targetInfo.Mode().Perm())
	}
}

func TestUpsertFileRejectsConflictingTargetWithoutReplace(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "source.exe")
	if err := os.WriteFile(sourcePath, []byte("new-content"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	targetDir := filepath.Join(tempDir, "releases", "desktop", "0.2.4")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	targetPath := filepath.Join(targetDir, "ZenMind-0.2.4-x64.exe")
	if err := os.WriteFile(targetPath, []byte("old-content"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	_, err := UpsertFile(ctx, UpsertFileOptions{
		DBPath:      filepath.Join(tempDir, "installers.sqlite"),
		ReleaseRoot: filepath.Join(tempDir, "releases"),
		Key:         "windows",
		Version:     "0.2.4",
		Source:      sourcePath,
		FileName:    "ZenMind-0.2.4-x64.exe",
	})
	if err == nil {
		t.Fatalf("expected conflict error")
	}

	installer, err := UpsertFile(ctx, UpsertFileOptions{
		DBPath:      filepath.Join(tempDir, "installers.sqlite"),
		ReleaseRoot: filepath.Join(tempDir, "releases"),
		Key:         "windows",
		Version:     "0.2.4",
		Source:      sourcePath,
		FileName:    "ZenMind-0.2.4-x64.exe",
		Replace:     true,
	})
	if err != nil {
		t.Fatalf("replace upsert: %v", err)
	}
	if installer.SizeBytes != int64(len("new-content")) {
		t.Fatalf("unexpected replacement installer: %#v", installer)
	}
}

func TestUpsertFileRepairsExistingFileMode(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "source.dmg")
	sourceContent := []byte("same-content")
	if err := os.WriteFile(sourcePath, sourceContent, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	targetDir := filepath.Join(tempDir, "releases", "desktop", "0.2.4")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	targetPath := filepath.Join(targetDir, "ZenMind-macOS-arm64.dmg")
	if err := os.WriteFile(targetPath, sourceContent, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	if _, err := UpsertFile(ctx, UpsertFileOptions{
		DBPath:      filepath.Join(tempDir, "installers.sqlite"),
		ReleaseRoot: filepath.Join(tempDir, "releases"),
		Key:         "mac",
		Version:     "0.2.4",
		Source:      sourcePath,
		FileName:    "ZenMind-macOS-arm64.dmg",
	}); err != nil {
		t.Fatalf("upsert existing file: %v", err)
	}
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if targetInfo.Mode().Perm() != 0o644 {
		t.Fatalf("target mode = %o, want 644", targetInfo.Mode().Perm())
	}
}

func TestUpsertFileRejectsInvalidKey(t *testing.T) {
	_, err := UpsertFile(context.Background(), UpsertFileOptions{Key: "linux"})
	if !errors.Is(err, ErrInvalidInstallerKey) {
		t.Fatalf("expected invalid key, got %v", err)
	}
}
