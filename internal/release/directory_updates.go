package release

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// DirectoryUpdateCatalog serves public files without consulting database metadata.
// Private sidecars retain descriptions and Admin history; they never publish a file.
type DirectoryUpdateCatalog struct {
	root *os.Root
	mu   sync.Mutex
}

func OpenDirectoryUpdates(ctx context.Context, dir string, legacy *SQLiteCatalog) (*DirectoryUpdateCatalog, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	c := &DirectoryUpdateCatalog{root: root}
	for _, d := range []string{".admin", ".disabled"} {
		if err = root.MkdirAll(d, 0755); err != nil {
			root.Close()
			return nil, err
		}
	}
	if legacy != nil {
		if err = c.importLegacy(ctx, legacy); err != nil {
			root.Close()
			return nil, err
		}
	}
	return c, nil
}
func (c *DirectoryUpdateCatalog) Close() error { return c.root.Close() }
func (c *DirectoryUpdateCatalog) read(path string, limit int64) ([]byte, os.FileInfo, error) {
	info, err := c.root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, ErrDesktopUpdateNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, ErrInvalidDesktopUpdate
	}
	f, err := c.root.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, ErrInvalidDesktopUpdate
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit || !json.Valid(data) {
		return nil, nil, ErrInvalidDesktopUpdate
	}
	return data, info, nil
}
func (c *DirectoryUpdateCatalog) atomicWrite(path string, data []byte) error {
	temp := filepath.Join(filepath.Dir(path), ".write-"+rand.Text())
	f, err := c.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer c.root.Remove(temp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return c.root.Rename(temp, path)
}
func (c *DirectoryUpdateCatalog) GetPublicJSON(_ context.Context, name string) ([]byte, error) {
	if !ValidUpdateName(name) {
		return nil, ErrDesktopUpdateNotFound
	}
	data, _, err := c.read(name, MaxDesktopManifestBytes)
	return data, err
}
func (c *DirectoryUpdateCatalog) GetPublicUpdate(ctx context.Context, name string) (DesktopManifest, error) {
	data, err := c.GetPublicJSON(ctx, name)
	if err != nil {
		return DesktopManifest{}, err
	}
	return decodeFeedManifest(string(data))
}
func (c *DirectoryUpdateCatalog) history(name string) ([]UpdateFeed, error) {
	data, _, err := c.read(filepath.Join(".admin", name), 64*1024*1024)
	if errors.Is(err, ErrDesktopUpdateNotFound) {
		return []UpdateFeed{}, nil
	}
	if err != nil {
		return nil, err
	}
	var items []UpdateFeed
	err = json.Unmarshal(data, &items)
	return items, err
}
func (c *DirectoryUpdateCatalog) GetUpdateFeed(_ context.Context, name string) (UpdateFeed, error) {
	if !ValidUpdateName(name) {
		return UpdateFeed{}, ErrDesktopUpdateNotFound
	}
	enabled := true
	data, info, err := c.read(name, MaxDesktopManifestBytes)
	if errors.Is(err, ErrDesktopUpdateNotFound) {
		enabled = false
		data, info, err = c.read(filepath.Join(".disabled", name), MaxDesktopManifestBytes)
	}
	if err != nil {
		return UpdateFeed{}, err
	}
	manifest, err := decodeFeedManifest(string(data))
	if err != nil {
		return UpdateFeed{}, err
	}
	history, err := c.history(name)
	if err != nil {
		return UpdateFeed{}, err
	}
	item := UpdateFeed{Name: name, Enabled: enabled, Manifest: &manifest, UpdatedAt: info.ModTime().UTC().Format(time.RFC3339Nano)}
	if len(history) > 0 {
		last := history[len(history)-1]
		item.Revision = last.Revision
		item.Description = last.Description
		item.UpdatedBy = last.UpdatedBy
	}
	item.ETag = fmt.Sprintf("%x-%t-%d", sha256.Sum256(data), enabled, item.Revision)
	return item, nil
}
func (c *DirectoryUpdateCatalog) ListUpdateFeeds(ctx context.Context) ([]UpdateFeed, error) {
	names := map[string]bool{}
	for _, dir := range []string{".", ".disabled"} {
		f, err := c.root.Open(dir)
		if err != nil {
			return nil, err
		}
		entries, err := f.ReadDir(-1)
		f.Close()
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if ValidUpdateName(e.Name()) && e.Type().IsRegular() {
				names[e.Name()] = true
			}
		}
	}
	items := []UpdateFeed{}
	for name := range names {
		item, err := c.GetUpdateFeed(ctx, name)
		if errors.Is(err, ErrDesktopUpdateNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		item.Manifest = nil
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}
func (c *DirectoryUpdateCatalog) UpdateFeedHistory(_ context.Context, name string) ([]UpdateFeed, error) {
	if !ValidUpdateName(name) {
		return nil, ErrDesktopUpdateNotFound
	}
	items, err := c.history(name)
	if err != nil {
		return nil, err
	}
	result := []UpdateFeed{}
	for i := len(items) - 1; i >= 0 && len(result) < 20; i-- {
		result = append(result, items[i])
	}
	return result, nil
}
func (c *DirectoryUpdateCatalog) SaveUpdateFeed(ctx context.Context, name string, input UpdateFeedInput, actor int64) (UpdateFeed, error) {
	if !ValidUpdateName(name) || input.Enabled == nil || actor <= 0 || input.Revision < 0 || len([]rune(input.Description)) > 500 {
		return UpdateFeed{}, ErrInvalidDesktopUpdate
	}
	if err := ValidateDesktopManifest(input.Manifest); err != nil {
		return UpdateFeed{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	current, err := c.GetUpdateFeed(ctx, name)
	if err != nil && !errors.Is(err, ErrDesktopUpdateNotFound) {
		return UpdateFeed{}, err
	}
	if current.Revision != input.Revision || current.ETag != input.ETag {
		return UpdateFeed{}, ErrUpdateConflict
	}
	history, err := c.history(name)
	if err != nil {
		return UpdateFeed{}, err
	}
	next := int64(1)
	if len(history) > 0 {
		next = history[len(history)-1].Revision + 1
	}
	item := UpdateFeed{Name: name, Description: input.Description, Enabled: *input.Enabled, Revision: next, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), UpdatedBy: actor, Manifest: &input.Manifest}
	history = append(history, item)
	metadata, err := json.Marshal(history)
	if err != nil {
		return UpdateFeed{}, err
	}
	if len(metadata) > 64*1024*1024 {
		return UpdateFeed{}, fmt.Errorf("history file too large")
	}
	data, err := json.MarshalIndent(input.Manifest, "", "  ")
	if err != nil {
		return UpdateFeed{}, err
	}
	data = append(data, '\n')
	path, other := name, filepath.Join(".disabled", name)
	if !item.Enabled {
		path, other = other, path
	}
	// Serialize Admin writes. External publishers should coordinate with Admin and use rename.
	if err = c.atomicWrite(path, data); err != nil {
		return UpdateFeed{}, err
	}
	if err = c.root.Remove(other); err != nil && !errors.Is(err, os.ErrNotExist) {
		return UpdateFeed{}, err
	}
	if err = c.atomicWrite(filepath.Join(".admin", name), metadata); err != nil {
		return UpdateFeed{}, err
	}
	return c.GetUpdateFeed(ctx, name)
}
func (c *DirectoryUpdateCatalog) importLegacy(ctx context.Context, legacy *SQLiteCatalog) error {
	const marker = ".admin/.sqlite-exported"
	if _, err := c.root.Stat(marker); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	items, err := legacy.ListUpdateFeeds(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		current, err := legacy.GetUpdateFeed(ctx, item.Name)
		if err != nil {
			return err
		}
		// Export all history, not only the 20 displayed by Admin. Never modify SQLite.
		rows, err := legacy.db.QueryContext(ctx, `SELECT `+feedColumns+`,r.MANIFEST_ FROM update_feed_revision r WHERE r.NAME_=? ORDER BY r.REVISION_`, item.Name)
		if err != nil {
			return err
		}
		history := []UpdateFeed{}
		for rows.Next() {
			record, e := scanFeed(rows, true)
			if e != nil {
				rows.Close()
				return e
			}
			history = append(history, record)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		sidecar := filepath.Join(".admin", item.Name)
		if _, err = c.root.Lstat(sidecar); errors.Is(err, os.ErrNotExist) {
			data, e := json.Marshal(history)
			if e != nil {
				return e
			}
			if e = c.atomicWrite(sidecar, data); e != nil {
				return e
			}
		} else if err != nil {
			return err
		}
		// An existing public or disabled file always wins over legacy data.
		_, pubErr := c.root.Lstat(item.Name)
		_, offErr := c.root.Lstat(filepath.Join(".disabled", item.Name))
		if errors.Is(pubErr, os.ErrNotExist) && errors.Is(offErr, os.ErrNotExist) {
			path := item.Name
			if !current.Enabled {
				path = filepath.Join(".disabled", path)
			}
			data, e := json.MarshalIndent(current.Manifest, "", "  ")
			if e != nil {
				return e
			}
			if e = c.atomicWrite(path, data); e != nil {
				return e
			}
		} else if pubErr != nil && !errors.Is(pubErr, os.ErrNotExist) {
			return pubErr
		} else if offErr != nil && !errors.Is(offErr, os.ErrNotExist) {
			return offErr
		}
	}
	return c.atomicWrite(marker, []byte("true\n"))
}
