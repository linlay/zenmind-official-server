package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type UpsertFileOptions struct {
	DBPath      string
	ReleaseRoot string
	Key         string
	Version     string
	Source      string
	FileName    string
	Replace     bool
}

func UpsertFile(ctx context.Context, opts UpsertFileOptions) (Installer, error) {
	key := strings.TrimSpace(opts.Key)
	version := strings.TrimSpace(opts.Version)
	source := strings.TrimSpace(opts.Source)
	fileName := strings.TrimSpace(opts.FileName)
	releaseRoot := strings.TrimSpace(opts.ReleaseRoot)

	if !IsAllowedInstallerKey(key) {
		return Installer{}, ErrInvalidInstallerKey
	}
	if version == "" || source == "" || fileName == "" || releaseRoot == "" {
		return Installer{}, fmt.Errorf("%w: key, version, source, filename, and release root are required", ErrInvalidInstaller)
	}
	if err := validatePathSegment(version, "version"); err != nil {
		return Installer{}, err
	}
	if err := validatePathSegment(fileName, "filename"); err != nil {
		return Installer{}, err
	}

	sourceInfo, err := os.Stat(source)
	if err != nil {
		return Installer{}, err
	}
	if sourceInfo.IsDir() {
		return Installer{}, fmt.Errorf("%w: source must be a file", ErrInvalidInstaller)
	}

	targetDir := filepath.Join(releaseRoot, "desktop", version)
	targetPath := filepath.Join(targetDir, fileName)
	sourceSHA, err := fileSHA256(source)
	if err != nil {
		return Installer{}, err
	}

	if targetInfo, err := os.Stat(targetPath); err == nil {
		if targetInfo.IsDir() {
			return Installer{}, fmt.Errorf("%w: target is a directory", ErrInvalidInstaller)
		}
		targetSHA, err := fileSHA256(targetPath)
		if err != nil {
			return Installer{}, err
		}
		if targetSHA != sourceSHA && !opts.Replace {
			return Installer{}, fmt.Errorf("target file already exists with different content: %s", targetPath)
		}
		if targetSHA != sourceSHA {
			if err := copyFileAtomic(source, targetPath); err != nil {
				return Installer{}, err
			}
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return Installer{}, err
		}
		if err := copyFileAtomic(source, targetPath); err != nil {
			return Installer{}, err
		}
	} else {
		return Installer{}, err
	}
	if err := os.Chmod(targetPath, 0o644); err != nil {
		return Installer{}, err
	}

	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		return Installer{}, err
	}
	targetSHA, err := fileSHA256(targetPath)
	if err != nil {
		return Installer{}, err
	}

	catalog, err := OpenSQLite(ctx, opts.DBPath)
	if err != nil {
		return Installer{}, err
	}
	defer catalog.Close()
	if err := catalog.EnsureSchema(ctx); err != nil {
		return Installer{}, err
	}

	installer := Installer{
		Key:       key,
		Available: true,
		Version:   version,
		Href:      NewInstallerHref(version, fileName),
		FileName:  fileName,
		SizeBytes: targetInfo.Size(),
		SHA256:    targetSHA,
		UpdatedAt: time.Now().UTC(),
	}
	if err := catalog.UpsertInstaller(ctx, installer); err != nil {
		return Installer{}, err
	}
	return installer, nil
}

func validatePathSegment(value, label string) error {
	if value == "" || value != filepath.Base(value) || strings.ContainsAny(value, `/\`) {
		return fmt.Errorf("%w: invalid %s", ErrInvalidInstaller, label)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyFileAtomic(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()

	sourceFile, err := os.Open(source)
	if err != nil {
		temp.Close()
		return err
	}
	defer sourceFile.Close()
	if _, err := io.Copy(temp, sourceFile); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, target); err != nil {
		return err
	}
	cleanup = false
	return nil
}
