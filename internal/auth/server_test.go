package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestEnsureInitialAdminIsIdempotent(t *testing.T) {
	store := newMemoryStore()
	ctx := context.Background()

	if err := EnsureInitialAdmin(ctx, store, "Admin@ZenMind.cc", "secret-one"); err != nil {
		t.Fatalf("first admin init failed: %v", err)
	}
	if err := EnsureInitialAdmin(ctx, store, "admin@zenmind.cc", "secret-two"); err != nil {
		t.Fatalf("second admin init failed: %v", err)
	}

	user, err := store.FindLocalUserByEmail(ctx, "admin@zenmind.cc")
	if err != nil {
		t.Fatalf("admin not found: %v", err)
	}
	if user.ID != 1 || user.Role != "admin" || !user.Enabled {
		t.Fatalf("unexpected admin: %#v", user)
	}
}

func TestLoginMeAndLogout(t *testing.T) {
	handler, store := testHandler(t)
	_ = store

	loginBody := bytes.NewBufferString(`{"email":"admin@zenmind.cc","password":"correct-password"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody)
	loginRec := httptest.NewRecorder()
	handler.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status = %d body = %s", loginRec.Code, loginRec.Body.String())
	}
	cookies := loginRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "test_session" || !cookies[0].HttpOnly {
		t.Fatalf("unexpected login cookies: %#v", cookies)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meReq.AddCookie(cookies[0])
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusOK {
		t.Fatalf("me status = %d body = %s", meRec.Code, meRec.Body.String())
	}
	var me map[string]map[string]any
	if err := json.NewDecoder(meRec.Body).Decode(&me); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	if me["user"]["email"] != "admin@zenmind.cc" {
		t.Fatalf("unexpected me response: %#v", me)
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	logoutReq.AddCookie(cookies[0])
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout status = %d body = %s", logoutRec.Code, logoutRec.Body.String())
	}

	meAfterLogoutReq := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meAfterLogoutReq.AddCookie(cookies[0])
	meAfterLogoutRec := httptest.NewRecorder()
	handler.ServeHTTP(meAfterLogoutRec, meAfterLogoutReq)
	if meAfterLogoutRec.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout status = %d body = %s", meAfterLogoutRec.Code, meAfterLogoutRec.Body.String())
	}
}

func TestLoginRejectsBadPassword(t *testing.T) {
	handler, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBufferString(`{"email":"admin@zenmind.cc","password":"wrong"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("bad password set cookies: %#v", rec.Result().Cookies())
	}
}

func TestMeWithoutSessionIsUnauthorized(t *testing.T) {
	handler, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestGoogleStartRedirectsAndSetsStateCookie(t *testing.T) {
	handler, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/google/start", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "accounts.example.test" || parsed.Path != "/auth" {
		t.Fatalf("unexpected location %q", location)
	}
	var stateCookie *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "test_session_oauth_state" {
			stateCookie = cookie
			break
		}
	}
	if stateCookie == nil || stateCookie.Value == "" || !stateCookie.HttpOnly {
		t.Fatalf("missing oauth state cookie: %#v", rec.Result().Cookies())
	}
	if parsed.Query().Get("state") != stateCookie.Value {
		t.Fatalf("redirect state and cookie state differ")
	}
}

func TestGoogleCallbackRejectsStateMismatch(t *testing.T) {
	handler, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=actual&code=test-code", nil)
	req.AddCookie(&http.Cookie{Name: "test_session_oauth_state", Value: "expected"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "http://localhost:5173/login?error=invalid_state" {
		t.Fatalf("unexpected failure redirect %q", rec.Header().Get("Location"))
	}
}

func TestGoogleCallbackCreatesSession(t *testing.T) {
	handler, store := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=expected&code=test-code", nil)
	req.AddCookie(&http.Cookie{Name: "test_session_oauth_state", Value: "expected"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "http://localhost:5173/login" {
		t.Fatalf("unexpected success redirect %q", rec.Header().Get("Location"))
	}

	var sessionCookie *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "test_session" && cookie.Value != "" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("missing session cookie: %#v", rec.Result().Cookies())
	}

	meReq := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meReq.AddCookie(sessionCookie)
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("me status = %d body = %s", meRec.Code, meRec.Body.String())
	}

	if len(store.google) != 1 {
		t.Fatalf("expected one google user, got %#v", store.google)
	}
}

func testHandler(t *testing.T) (http.Handler, *memoryStore) {
	t.Helper()

	store := newMemoryStore()
	if err := EnsureInitialAdmin(context.Background(), store, "admin@zenmind.cc", "correct-password"); err != nil {
		t.Fatalf("init admin: %v", err)
	}
	server := NewServer(store, ServerOptions{
		CookieName:     "test_session",
		SessionTTL:     time.Hour,
		Google:         fakeGoogleProvider{},
		AuthSuccessURL: "http://localhost:5173/login",
		AuthFailureURL: "http://localhost:5173/login",
	})
	return server.Routes(), store
}

type fakeGoogleProvider struct{}

func (fakeGoogleProvider) Configured() bool {
	return true
}

func (fakeGoogleProvider) AuthCodeURL(state string) string {
	return "https://accounts.example.test/auth?state=" + state
}

func (fakeGoogleProvider) ExchangeCode(context.Context, string) (GoogleIdentity, error) {
	return GoogleIdentity{
		Subject: "google-subject",
		Email:   "google-user@example.com",
		Name:    "Google User",
		Picture: "https://example.com/avatar.png",
	}, nil
}
