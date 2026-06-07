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

func TestEmailCodeStartSendsCode(t *testing.T) {
	handler, store, mailer := testHandlerWithMailer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/email-code/start", bytes.NewBufferString(`{"email":"New@Example.com"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if mailer.to != "new@example.com" || !validEmailCode(mailer.code) {
		t.Fatalf("unexpected email delivery: %#v", mailer)
	}
	if len(store.codes) != 1 || store.codes[0].email != "new@example.com" {
		t.Fatalf("unexpected stored codes: %#v", store.codes)
	}
}

func TestEmailCodeVerifyCreatesSessionAndConsumesCode(t *testing.T) {
	handler, store, mailer := testHandlerWithMailer(t)

	startReq := httptest.NewRequest(http.MethodPost, "/api/auth/email-code/start", bytes.NewBufferString(`{"email":"new@example.com"}`))
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("start status = %d body = %s", startRec.Code, startRec.Body.String())
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/auth/email-code/verify", bytes.NewBufferString(`{"email":"new@example.com","code":"`+mailer.code+`"}`))
	verifyRec := httptest.NewRecorder()
	handler.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body = %s", verifyRec.Code, verifyRec.Body.String())
	}
	cookies := verifyRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "test_session" {
		t.Fatalf("unexpected verify cookies: %#v", cookies)
	}
	if len(store.email) != 1 {
		t.Fatalf("expected email-code user, got %#v", store.email)
	}

	reuseReq := httptest.NewRequest(http.MethodPost, "/api/auth/email-code/verify", bytes.NewBufferString(`{"email":"new@example.com","code":"`+mailer.code+`"}`))
	reuseRec := httptest.NewRecorder()
	handler.ServeHTTP(reuseRec, reuseReq)
	if reuseRec.Code != http.StatusUnauthorized {
		t.Fatalf("reuse status = %d body = %s", reuseRec.Code, reuseRec.Body.String())
	}
}

func TestEmailCodeRejectsInvalidEmail(t *testing.T) {
	handler, _, _ := testHandlerWithMailer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/email-code/start", bytes.NewBufferString(`{"email":"not-email"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestDownloadStatsAndEvent(t *testing.T) {
	handler, store := testHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/downloads/events", bytes.NewBufferString(`{"installerKey":"mac"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("event status = %d body = %s", rec.Code, rec.Body.String())
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		total := store.stats["mac"]
		store.mu.Unlock()
		if total == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	statsReq := httptest.NewRequest(http.MethodGet, "/api/downloads/stats", nil)
	statsRec := httptest.NewRecorder()
	handler.ServeHTTP(statsRec, statsReq)
	if statsRec.Code != http.StatusOK {
		t.Fatalf("stats status = %d body = %s", statsRec.Code, statsRec.Body.String())
	}
	var body struct {
		Totals map[string]int64 `json:"totals"`
	}
	if err := json.NewDecoder(statsRec.Body).Decode(&body); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if body.Totals["mac"] != 1 || body.Totals["windows"] != 0 {
		t.Fatalf("unexpected totals: %#v", body.Totals)
	}
}

func TestDownloadEventRejectsUnknownInstaller(t *testing.T) {
	handler, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/downloads/events", bytes.NewBufferString(`{"installerKey":"linux"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
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

func TestDesktopSSOSessionCreatesSessionFromGoogleIDToken(t *testing.T) {
	handler, store := testHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/desktop-sso/session", bytes.NewBufferString(`{"provider":"google","id_token":"desktop-id-token"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "test_session" || !cookies[0].HttpOnly {
		t.Fatalf("unexpected desktop SSO cookies: %#v", cookies)
	}

	var body struct {
		OK   bool           `json:"ok"`
		User map[string]any `json:"user"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode desktop SSO response: %v", err)
	}
	if !body.OK || body.User["email"] != "desktop-user@example.com" {
		t.Fatalf("unexpected desktop SSO response: %#v", body)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meReq.AddCookie(cookies[0])
	meRec := httptest.NewRecorder()
	handler.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("me status = %d body = %s", meRec.Code, meRec.Body.String())
	}
	if len(store.google) != 1 {
		t.Fatalf("expected one google user, got %#v", store.google)
	}
}

func TestDesktopSSOSessionRejectsInvalidGoogleIDToken(t *testing.T) {
	handler, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/desktop-sso/session", bytes.NewBufferString(`{"provider":"google","id_token":"invalid"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("invalid desktop SSO set cookies: %#v", rec.Result().Cookies())
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

func testHandlerWithMailer(t *testing.T) (http.Handler, *memoryStore, *fakeMailer) {
	t.Helper()

	store := newMemoryStore()
	if err := EnsureInitialAdmin(context.Background(), store, "admin@zenmind.cc", "correct-password"); err != nil {
		t.Fatalf("init admin: %v", err)
	}
	mailer := &fakeMailer{}
	server := NewServer(store, ServerOptions{
		CookieName:     "test_session",
		SessionTTL:     time.Hour,
		Google:         fakeGoogleProvider{},
		AuthSuccessURL: "http://localhost:5173/login",
		AuthFailureURL: "http://localhost:5173/login",
		Mailer:         mailer,
	})
	return server.Routes(), store, mailer
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

func (fakeGoogleProvider) VerifyIDToken(_ context.Context, rawToken string) (GoogleIdentity, error) {
	if rawToken != "desktop-id-token" {
		return GoogleIdentity{}, context.Canceled
	}
	return GoogleIdentity{
		Subject: "desktop-google-subject",
		Email:   "desktop-user@example.com",
		Name:    "Desktop User",
		Picture: "https://example.com/desktop-avatar.png",
	}, nil
}

type fakeMailer struct {
	to   string
	code string
}

func (m *fakeMailer) SendEmailCode(_ context.Context, to, code string) error {
	m.to = to
	m.code = code
	return nil
}
