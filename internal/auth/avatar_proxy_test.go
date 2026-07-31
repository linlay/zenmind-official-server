package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func loginAvatarTestUser(t *testing.T, handler http.Handler) *http.Cookie {
	t.Helper()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/login",
		bytes.NewBufferString(`{"email":"admin@zenmind.cc","password":"correct-password"}`),
	)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %#v", cookies)
	}
	return cookies[0]
}

func avatarTestServer(
	t *testing.T,
	upstream *httptest.Server,
	avatarURL string,
) (*Server, http.Handler, *memoryStore, *http.Cookie) {
	t.Helper()
	store := newMemoryStore()
	if err := EnsureInitialAdmin(context.Background(), store, "admin@zenmind.cc", "correct-password"); err != nil {
		t.Fatalf("init admin: %v", err)
	}
	store.mu.Lock()
	user := store.users[1]
	user.AvatarURL = avatarURL
	store.users[1] = user
	store.mu.Unlock()

	server := NewServer(store, ServerOptions{
		CookieName:   "test_session",
		SessionTTL:   time.Hour,
		DesktopJWT:   testDesktopJWTConfig(t),
		AuthLoginURL: "/login",
		AvatarProxy: AvatarProxyConfig{
			Enabled:        true,
			PublicOrigin:   "https://www.zenmind.cc",
			AllowedOrigins: []string{upstream.URL},
			CacheDir:       t.TempDir(),
			CacheTTL:       time.Hour,
			FetchTimeout:   time.Second,
			MaxBytes:       1024,
		},
	})
	server.avatarProxy.httpClient = upstream.Client()
	handler := server.Routes()
	return server, handler, store, loginAvatarTestUser(t, handler)
}

func TestAvatarProxyHidesUpstreamURLAndCachesAuthenticatedResponse(t *testing.T) {
	var requestCount atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Fatalf("upstream received credentials: %#v", r.Header)
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("\x89PNG\r\n\x1a\navatar"))
	}))
	defer upstream.Close()

	server, handler, _, cookie := avatarTestServer(t, upstream, upstream.URL+"/avatar.png")

	meRequest := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meRequest.AddCookie(cookie)
	meRecorder := httptest.NewRecorder()
	handler.ServeHTTP(meRecorder, meRequest)
	if meRecorder.Code != http.StatusOK {
		t.Fatalf("me status = %d body = %s", meRecorder.Code, meRecorder.Body.String())
	}
	var meBody struct {
		User struct {
			AvatarURL string `json:"avatarUrl"`
		} `json:"user"`
	}
	if err := json.NewDecoder(meRecorder.Body).Decode(&meBody); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	expectedURL := server.avatarProxy.publicURL(server.storeUserForAvatarTest(t))
	if meBody.User.AvatarURL != expectedURL ||
		!strings.HasPrefix(meBody.User.AvatarURL, "https://www.zenmind.cc/api/auth/avatar/") ||
		strings.Contains(meBody.User.AvatarURL, upstream.URL) {
		t.Fatalf("unexpected public avatar URL %q", meBody.User.AvatarURL)
	}

	avatarPath := strings.TrimPrefix(meBody.User.AvatarURL, "https://www.zenmind.cc")
	for iteration := 0; iteration < 2; iteration++ {
		request := httptest.NewRequest(http.MethodGet, avatarPath, nil)
		request.AddCookie(cookie)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "image/png" {
			t.Fatalf("avatar attempt %d status = %d headers = %#v body = %q", iteration, recorder.Code, recorder.Header(), recorder.Body.String())
		}
	}
	if requestCount.Load() != 1 {
		t.Fatalf("upstream request count = %d, want 1", requestCount.Load())
	}
	cacheEntries, err := os.ReadDir(filepath.Join(server.avatarProxy.cacheDir, "1"))
	if err != nil || len(cacheEntries) != 1 {
		t.Fatalf("cache entries = %#v err = %v", cacheEntries, err)
	}
}

func (s *Server) storeUserForAvatarTest(t *testing.T) User {
	t.Helper()
	store, ok := s.store.(*memoryStore)
	if !ok {
		t.Fatalf("store type = %T", s.store)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.users[1]
}

func TestAvatarProxyRequiresSessionAndTrustedOrigin(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("avatar"))
	}))
	defer upstream.Close()

	server, handler, _, cookie := avatarTestServer(t, upstream, "https://untrusted.example.test/avatar.png")
	user := server.storeUserForAvatarTest(t)
	if got := server.avatarProxy.publicURL(user); got != "" {
		t.Fatalf("untrusted avatar public URL = %q", got)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/auth/avatar/"+avatarVersion(user), nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated avatar status = %d body = %s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/auth/avatar/"+avatarVersion(user), nil)
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("untrusted avatar status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestAvatarProxyKeepsAccountWithoutAvatarOnInitialsFallback(t *testing.T) {
	proxy := newAvatarProxy(AvatarProxyConfig{
		Enabled:        true,
		PublicOrigin:   "https://www.zenmind.cc/",
		AllowedOrigins: []string{"https://lh3.googleusercontent.com"},
	})
	user := User{
		ID:           9,
		Email:        "email-user@example.com",
		DisplayName:  "Email User",
		AuthProvider: "local",
	}
	if got := proxy.publicURL(user); got != "" {
		t.Fatalf("account without avatar URL = %q, want empty fallback", got)
	}
}

func TestAvatarProxyURLIsUsedInDesktopJWT(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write([]byte("jpeg"))
	}))
	defer upstream.Close()

	server, handler, _, cookie := avatarTestServer(t, upstream, upstream.URL+"/avatar.jpg")
	csrfToken := csrfTokenForCookie(t, handler, cookie)
	request := httptest.NewRequest(http.MethodPost, "/api/auth/desktop-sso/token", nil)
	request.AddCookie(cookie)
	request.Header.Set("X-CSRF-Token", csrfToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("token status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	claims := decodeTestJWTClaims(t, body.AccessToken)
	expected := server.avatarProxy.publicURL(server.storeUserForAvatarTest(t))
	if claims["picture"] != expected {
		t.Fatalf("JWT picture = %#v, want %q", claims["picture"], expected)
	}
}
