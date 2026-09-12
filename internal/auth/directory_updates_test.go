package auth

import (
	"context"
	"github.com/linlay/zenmind-official-server/internal/release"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicDirectoryJSON(t *testing.T) {
	dir := t.TempDir()
	files, err := release.OpenDirectoryUpdates(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	h := NewServer(newMemoryStore(), ServerOptions{DesktopUpdates: files}).Routes()
	raw := "{\n  \"custom\": true\n}\n"
	os.WriteFile(filepath.Join(dir, "desktop-beta.json"), []byte(raw), 0644)
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/api/updates/desktop-beta.json", nil))
	if r.Code != 200 || r.Body.String() != raw || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(r.Code, r.Body.String())
	}
	os.Remove(filepath.Join(dir, "desktop-beta.json"))
	r = httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/api/updates/desktop-beta.json", nil))
	if r.Code != 404 {
		t.Fatal(r.Code)
	}
}
