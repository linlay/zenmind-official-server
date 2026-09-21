package auth

import (
	"context"
	"encoding/json"
	"github.com/linlay/zenmind-official-server/internal/release"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminNamedUpdates(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { testAdminNamedUpdates(t, false) })
	t.Run("directory", func(t *testing.T) { testAdminNamedUpdates(t, true) })
}
func testAdminNamedUpdates(t *testing.T, directory bool) {
	ctx := context.Background()
	catalog, err := release.OpenSQLite(ctx, filepath.Join(t.TempDir(), "site.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	if err := catalog.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	var provider release.DesktopUpdateCatalog = catalog
	if directory {
		files, err := release.OpenDirectoryUpdates(ctx, t.TempDir(), catalog)
		if err != nil {
			t.Fatal(err)
		}
		defer files.Close()
		provider = files
	}
	store := newMemoryStore()
	if err := store.EnsureAdmin(ctx, "admin@example.com", "test-hash"); err != nil {
		t.Fatal(err)
	}
	user, err := store.FindLocalUserByEmail(ctx, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, user.ID, tokenHash("session"), "csrf", time.Now().Add(time.Hour), "test", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(store, ServerOptions{CookieName: "session", DesktopUpdates: provider}).Routes()
	request := func(method, path, body string, session, csrf bool, origin string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "https://example.com"+path, strings.NewReader(body))
		if session {
			req.AddCookie(&http.Cookie{Name: "session", Value: "session"})
		}
		if csrf {
			req.Header.Set("X-CSRF-Token", "csrf")
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	check := func(rec *httptest.ResponseRecorder, status int) {
		t.Helper()
		if rec.Code != status {
			t.Fatalf("want %d got %d: %s", status, rec.Code, rec.Body.String())
		}
	}
	raw := `{"schemaVersion":1,"productId":"cutej","version":"0.6.0-beta.1","publishedAt":"2026-09-12T08:00:00Z","releaseNotes":{"en-US":["Update"]},"artifacts":{"darwin-arm64":{"url":"https://example.com/app.zip","size":12,"sha256":"` + strings.Repeat("a", 64) + `"}}}`
	body := `{"description":"Beta","enabled":true,"revision":0,"manifest":` + raw + `}`
	const admin = "/api/admin/updates/desktop-beta.json"
	check(request("GET", "/api/admin/updates", "", false, false, ""), 401)
	check(request("PUT", admin, body, false, false, ""), 401)
	check(request("PUT", admin, body, true, false, ""), 403)
	check(request("PUT", admin, body, true, true, "https://evil.example.com"), 403)
	// Every Admin route checks the current server-side role, not frontend state.
	store.mu.Lock()
	u := store.users[user.ID]
	u.Role = "user"
	store.users[user.ID] = u
	store.mu.Unlock()
	for _, p := range []string{"/api/admin/updates", admin, admin + "/history"} {
		check(request("GET", p, "", true, false, ""), 403)
	}
	check(request("PUT", admin, body, true, true, ""), 403)
	store.mu.Lock()
	u.Role = "admin"
	store.users[user.ID] = u
	store.mu.Unlock()
	check(request("GET", "/api/updates/desktop-beta.json", "", false, false, ""), 404)
	check(request("PUT", admin, body, true, true, "https://example.com"), 200)
	rec := request("GET", "/api/updates/desktop-beta.json", "", false, false, "")
	check(rec, 200)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
	if strings.Contains(rec.Body.String(), `"channel"`) {
		t.Fatal("public feed emitted channel")
	}
	var m release.DesktopManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || m.Version != "0.6.0-beta.1" {
		t.Fatal(m, err)
	}
	check(request("GET", "/api/updates/desktop-latest.json", "", false, false, ""), 404)
	check(request("PUT", admin, body, true, true, ""), 409)
	check(request("GET", "/api/admin/updates", "", true, false, ""), 200)
	check(request("GET", admin+"/history", "", true, false, ""), 200)
	disabled := strings.Replace(strings.Replace(body, `"revision":0`, `"revision":1`, 1), `"enabled":true`, `"enabled":false`, 1)
	if directory {
		current, err := provider.GetUpdateFeed(ctx, "desktop-beta.json")
		if err != nil {
			t.Fatal(err)
		}
		disabled = strings.Replace(disabled, `"revision":1`, `"revision":1,"etag":"`+current.ETag+`"`, 1)
	}
	check(request("PUT", admin, disabled, true, true, ""), 200)
	rec = request("GET", "/api/updates/desktop-beta.json", "", false, false, "")
	check(rec, 404)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cached 404")
	}
	check(request("PUT", admin, body+` {}`, true, true, ""), 400)
	check(request("PUT", admin, strings.Repeat("x", 300000), true, true, ""), 400)
	check(request("PUT", "/api/admin/updates/bad%2Fname.json", body, true, true, ""), 400)
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		check(request(method, "/api/updates/desktop-beta.json", body, true, true, ""), 405)
	}
	store.mu.Lock()
	u.Enabled = false
	store.users[user.ID] = u
	store.mu.Unlock()
	check(request("GET", admin, "", true, false, ""), 403)
}
func TestUpdateStoreUnavailable(t *testing.T) {
	handler := NewServer(newMemoryStore(), ServerOptions{}).Routes()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/updates/desktop-latest.json", nil))
	if rec.Code != 503 {
		t.Fatal(rec.Code)
	}
}
