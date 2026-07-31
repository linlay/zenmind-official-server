package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/linlay/zenmind-official-server/internal/release"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	store              Store
	cookieName         string
	cookieSecure       bool
	sessionTTL         time.Duration
	trustedProxyCIDRs  []netip.Prefix
	google             GoogleProvider
	authLoginURL       string
	authOrigin         string
	authSuccessURL     string
	authFailureURL     string
	ssoBridgeToken     string
	desktopSSOProvider string
	desktopTicketTTL   time.Duration
	desktopJWTSigner   *identityJWTSigner
	marketServerURL    string
	marketProxyToken   string
	marketJWTAudience  string
	marketJWTTTL       time.Duration
	mailer             Mailer
	installerCatalog   release.Catalog
	downloadStore      DownloadStore
	avatarProxy        *avatarProxy
	rateLimiter        *rateLimiter
	now                func() time.Time
}

type ServerOptions struct {
	CookieName         string
	CookieSecure       bool
	SessionTTL         time.Duration
	TrustedProxyCIDRs  []string
	Google             GoogleProvider
	AuthLoginURL       string
	AuthSuccessURL     string
	AuthFailureURL     string
	SSOBridgeToken     string
	DesktopSSOProvider string
	DesktopTicketTTL   time.Duration
	DesktopJWT         DesktopJWTConfig
	MarketServerURL    string
	MarketProxyToken   string
	MarketJWTAudience  string
	MarketJWTTTL       time.Duration
	Mailer             Mailer
	InstallerCatalog   release.Catalog
	DownloadStore      DownloadStore
	AvatarProxy        AvatarProxyConfig
}

func NewServer(store Store, opts ServerOptions) *Server {
	cookieName := opts.CookieName
	if cookieName == "" {
		cookieName = "zenmind_session"
	}
	sessionTTL := opts.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = 24 * time.Hour
	}
	desktopTicketTTL := opts.DesktopTicketTTL
	if desktopTicketTTL <= 0 {
		desktopTicketTTL = 2 * time.Minute
	}
	authLoginURL := strings.TrimSpace(opts.AuthLoginURL)
	if authLoginURL == "" {
		authLoginURL = "/login"
	}
	marketJWTAudience := strings.TrimSpace(opts.MarketJWTAudience)
	if marketJWTAudience == "" {
		marketJWTAudience = "market"
	}
	marketJWTTTL := opts.MarketJWTTTL
	if marketJWTTTL <= 0 {
		marketJWTTTL = 90 * time.Second
	}
	google := opts.Google
	if google == nil {
		google = disabledGoogleProvider{}
	}
	mailer := opts.Mailer
	if mailer == nil {
		mailer = disabledMailer{}
	}
	downloadStore := opts.DownloadStore
	if downloadStore == nil {
		if candidate, ok := store.(DownloadStore); ok {
			downloadStore = candidate
		} else {
			downloadStore = disabledDownloadStore{}
		}
	}

	return &Server{
		store:              store,
		cookieName:         cookieName,
		cookieSecure:       opts.CookieSecure,
		sessionTTL:         sessionTTL,
		trustedProxyCIDRs:  parseTrustedProxyCIDRs(opts.TrustedProxyCIDRs),
		google:             google,
		authLoginURL:       safeRelativeRedirect(authLoginURL),
		authOrigin:         originFromURL(opts.AuthSuccessURL),
		authSuccessURL:     strings.TrimSpace(opts.AuthSuccessURL),
		authFailureURL:     strings.TrimSpace(opts.AuthFailureURL),
		ssoBridgeToken:     strings.TrimSpace(opts.SSOBridgeToken),
		desktopSSOProvider: normalizeDesktopSSOProvider(opts.DesktopSSOProvider),
		desktopTicketTTL:   desktopTicketTTL,
		desktopJWTSigner:   newIdentityJWTSigner(opts.DesktopJWT),
		marketServerURL:    strings.TrimRight(strings.TrimSpace(opts.MarketServerURL), "/"),
		marketProxyToken:   strings.TrimSpace(opts.MarketProxyToken),
		marketJWTAudience:  marketJWTAudience,
		marketJWTTTL:       marketJWTTTL,
		mailer:             mailer,
		installerCatalog:   opts.InstallerCatalog,
		downloadStore:      downloadStore,
		avatarProxy:        newAvatarProxy(opts.AvatarProxy),
		rateLimiter:        newRateLimiter(),
		now:                time.Now,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/installers", s.installers)
	mux.HandleFunc("GET /api/downloads/stats", s.downloadStats)
	mux.HandleFunc("POST /api/downloads/events", s.downloadEvent)
	mux.HandleFunc("POST /api/auth/login", s.login)
	mux.HandleFunc("POST /api/auth/email-code/start", s.emailCodeStart)
	mux.HandleFunc("POST /api/auth/email-code/verify", s.emailCodeVerify)
	mux.HandleFunc("GET /api/auth/google/start", s.googleStart)
	mux.HandleFunc("GET /api/auth/google/callback", s.googleCallback)
	mux.HandleFunc("GET /api/v1/auth/google/callback", s.googleCallback)
	mux.HandleFunc("GET /api/auth/google/desktop/start", s.googleDesktopStart)
	mux.HandleFunc("GET /api/auth/desktop-sso/start", s.desktopSsoStart)
	mux.HandleFunc("GET /api/auth/desktop-sso/continue", s.desktopSsoContinue)
	mux.HandleFunc("POST /api/auth/desktop-sso/session", s.desktopSsoSession)
	mux.HandleFunc("POST /api/auth/desktop-sso/token", s.desktopSsoToken)
	mux.HandleFunc("GET /api/auth/sso/session", s.authentikSsoSession)
	mux.HandleFunc("GET /api/auth/csrf", s.csrf)
	mux.HandleFunc("GET /api/auth/me", s.me)
	mux.HandleFunc("GET /api/auth/avatar/{version}", s.avatar)
	mux.HandleFunc("POST /api/auth/logout", s.logout)
	mux.HandleFunc("/api/market/", s.marketProxy)
	return securityHeaders(mux)
}

func EnsureInitialAdmin(ctx context.Context, store Store, email, password string) error {
	if strings.TrimSpace(password) == "" {
		return ErrAdminPasswordEmpty
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return store.EnsureAdmin(ctx, email, string(hash))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) installers(w http.ResponseWriter, r *http.Request) {
	if s.installerCatalog == nil {
		writeError(w, http.StatusServiceUnavailable, "installers_unavailable", "Installer catalog is unavailable.")
		return
	}
	installers, err := s.installerCatalog.ListInstallers(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "installers_unavailable", "Installer catalog is unavailable.")
		return
	}
	visible := make([]release.Installer, 0, len(installers))
	for _, installer := range installers {
		if release.IsAllowedInstallerKey(installer.Key) {
			visible = append(visible, installer)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"installers": visible})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type emailCodeStartRequest struct {
	Email string `json:"email"`
}

type emailCodeVerifyRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type downloadEventRequest struct {
	InstallerKey string `json:"installerKey"`
	Version      string `json:"version"`
}

type desktopSsoSessionRequest struct {
	Provider string `json:"provider"`
	IDToken  string `json:"id_token"`
	Ticket   string `json:"ticket"`
}

var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

type desktopOAuthContext struct {
	OAuthState   string
	CallbackURL  string
	DesktopState string
}

var allowedInstallerKeys = map[string]bool{
	"mac":     true,
	"windows": true,
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.requireValidOrigin(w, r) {
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid login request.")
		return
	}
	rateKey := "admin:" + s.requestIP(r) + ":" + normalizeEmail(req.Email)
	if !s.rateLimiter.allow(rateKey, 5, 15*time.Minute, s.now()) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many login attempts. Please try again later.")
		return
	}

	user, err := s.store.FindLocalUserByEmail(r.Context(), req.Email)
	if errors.Is(err, ErrNotFound) {
		s.recordLogin(r, LoginLog{Email: req.Email, AuthMethod: "local", LoginResult: "failure", FailureReason: "invalid_credentials"})
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Email or password is incorrect.")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to read user account.")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		s.recordLogin(r, LoginLog{Email: req.Email, AuthMethod: "local", LoginResult: "failure", FailureReason: "invalid_credentials"})
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Email or password is incorrect.")
		return
	}
	if !user.Enabled {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "local", LoginResult: "failure", FailureReason: "account_disabled"})
		writeError(w, http.StatusForbidden, "account_disabled", "This account is disabled.")
		return
	}

	token, _, expiresAt, err := s.createSession(r, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to save session.")
		return
	}
	now := s.now().UTC()
	_ = s.store.TouchLastLogin(r.Context(), user.ID, now)
	user.LastLoginAt = &now
	s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "local", LoginResult: "success"})

	http.SetCookie(w, s.sessionCookie(token, expiresAt))
	writeJSON(w, http.StatusOK, map[string]any{"user": s.publicUser(user)})
}

func (s *Server) emailCodeStart(w http.ResponseWriter, r *http.Request) {
	if !s.requireValidOrigin(w, r) {
		return
	}
	var req emailCodeStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid verification request.")
		return
	}
	email := normalizeEmail(req.Email)
	if !validEmail(email) {
		writeError(w, http.StatusBadRequest, "invalid_email", "Please enter a valid email address.")
		return
	}
	now := s.now()
	if !s.rateLimiter.allow("email-send:address:"+email, 3, 15*time.Minute, now) ||
		!s.rateLimiter.allow("email-send:ip:"+s.requestIP(r), 10, 15*time.Minute, now) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many verification requests. Please try again later.")
		return
	}

	code, err := randomDigits(6)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to create verification code.")
		return
	}
	expiresAt := s.now().UTC().Add(10 * time.Minute)
	if err := s.store.SaveEmailCode(r.Context(), email, emailCodeHash(email, code), expiresAt); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to save verification code.")
		return
	}
	if err := s.mailer.SendEmailCode(r.Context(), email, code); err != nil {
		writeError(w, http.StatusInternalServerError, "email_not_configured", "Unable to send verification email.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "expiresAt": expiresAt})
}

func (s *Server) emailCodeVerify(w http.ResponseWriter, r *http.Request) {
	if !s.requireValidOrigin(w, r) {
		return
	}
	var req emailCodeVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid verification request.")
		return
	}
	email := normalizeEmail(req.Email)
	code := strings.TrimSpace(req.Code)
	if !s.rateLimiter.allow("email-verify:"+s.requestIP(r)+":"+email, 10, 15*time.Minute, s.now()) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many verification attempts. Please try again later.")
		return
	}
	if !validEmail(email) || !validEmailCode(code) {
		s.recordLogin(r, LoginLog{Email: email, AuthMethod: "email_code", LoginResult: "failure", FailureReason: "invalid_code"})
		writeError(w, http.StatusUnauthorized, "invalid_code", "Verification code is incorrect or expired.")
		return
	}

	if err := s.store.ConsumeEmailCode(r.Context(), email, emailCodeHash(email, code), s.now().UTC()); err != nil {
		s.recordLogin(r, LoginLog{Email: email, AuthMethod: "email_code", LoginResult: "failure", FailureReason: "invalid_code"})
		writeError(w, http.StatusUnauthorized, "invalid_code", "Verification code is incorrect or expired.")
		return
	}

	user, err := s.store.UpsertEmailCodeUser(r.Context(), email, s.requestIP(r))
	if err != nil {
		s.recordLogin(r, LoginLog{Email: email, AuthMethod: "email_code", LoginResult: "failure", FailureReason: "user_upsert_failed"})
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to save user account.")
		return
	}
	if !user.Enabled {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "email_code", LoginResult: "failure", FailureReason: "account_disabled"})
		writeError(w, http.StatusForbidden, "account_disabled", "This account is disabled.")
		return
	}

	token, _, expiresAt, err := s.createSession(r, user.ID)
	if err != nil {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "email_code", LoginResult: "failure", FailureReason: "session_create_failed"})
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to save session.")
		return
	}
	now := s.now().UTC()
	_ = s.store.TouchLastLogin(r.Context(), user.ID, now)
	user.LastLoginAt = &now
	s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "email_code", LoginResult: "success"})

	http.SetCookie(w, s.sessionCookie(token, expiresAt))
	writeJSON(w, http.StatusOK, map[string]any{"user": s.publicUser(user)})
}

func (s *Server) downloadStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.downloadStore.ListDownloadStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to read download stats.")
		return
	}
	totals := map[string]int64{}
	for key := range allowedInstallerKeys {
		totals[key] = 0
	}
	for _, stat := range stats {
		if allowedInstallerKeys[stat.InstallerKey] {
			totals[stat.InstallerKey] = stat.Total
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"totals": totals})
}

func (s *Server) downloadEvent(w http.ResponseWriter, r *http.Request) {
	var req downloadEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid download event.")
		return
	}
	installerKey := strings.TrimSpace(req.InstallerKey)
	if !allowedInstallerKeys[installerKey] {
		writeError(w, http.StatusBadRequest, "invalid_installer", "Unknown installer.")
		return
	}

	event := downloadEventFromRequest(r, installerKey, req.Version, s.now().UTC())
	event.ClientIP = s.requestIP(r)
	if err := s.downloadStore.RecordDownloadEvent(r.Context(), event); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to record download event.")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

func (s *Server) googleStart(w http.ResponseWriter, r *http.Request) {
	if !s.google.Configured() {
		s.redirectFailure(w, r, "google_not_configured")
		return
	}
	if !s.rateLimiter.allow("google:"+s.requestIP(r), 30, 15*time.Minute, s.now()) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many login attempts. Please try again later.")
		return
	}
	s.startGoogleOAuth(w, r, OAuthRequest{
		Kind:     "web",
		ReturnTo: safeRelativeRedirect(r.URL.Query().Get("return_to")),
	})
}

func (s *Server) googleDesktopStart(w http.ResponseWriter, r *http.Request) {
	if !s.google.Configured() {
		writeError(w, http.StatusServiceUnavailable, "google_not_configured", "Google login is not configured.")
		return
	}

	callbackURL := strings.TrimSpace(r.URL.Query().Get("callback"))
	desktopState := strings.TrimSpace(r.URL.Query().Get("state"))
	if !isAllowedDesktopCallbackURL(callbackURL) || desktopState == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "Desktop callback and state are required.")
		return
	}

	s.startGoogleOAuth(w, r, OAuthRequest{
		Kind:         "desktop",
		CallbackURL:  callbackURL,
		DesktopState: desktopState,
	})
}

func (s *Server) startGoogleOAuth(w http.ResponseWriter, r *http.Request, request OAuthRequest) {
	state, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to start Google login.")
		return
	}
	nonce, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to start Google login.")
		return
	}
	codeVerifier, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to start Google login.")
		return
	}
	request.Nonce = nonce
	request.CodeVerifier = codeVerifier
	request.ExpiresAt = s.now().UTC().Add(10 * time.Minute)
	if request.ReturnTo == "" {
		request.ReturnTo = "/"
	}
	if err := s.store.SaveOAuthRequest(r.Context(), tokenHash(state), request); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to save Google login request.")
		return
	}
	http.Redirect(w, r, s.google.AuthCodeURL(state, nonce, pkceChallenge(codeVerifier)), http.StatusFound)
}

func (s *Server) googleCallback(w http.ResponseWriter, r *http.Request) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	request, err := s.store.ConsumeOAuthRequest(r.Context(), tokenHash(state), s.now().UTC())
	if state == "" || errors.Is(err, ErrNotFound) {
		s.recordLogin(r, LoginLog{AuthMethod: "google", LoginResult: "failure", FailureReason: "invalid_state"})
		s.redirectFailure(w, r, "invalid_state")
		return
	}
	if err != nil {
		s.redirectFailure(w, r, "google_state_failed")
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		s.recordLogin(r, LoginLog{AuthMethod: "google", LoginResult: "failure", FailureReason: "missing_code"})
		s.redirectFailure(w, r, "missing_code")
		return
	}
	identity, err := s.google.ExchangeCode(r.Context(), code, request.CodeVerifier, request.Nonce)
	if err != nil {
		s.recordLogin(r, LoginLog{AuthMethod: "google", LoginResult: "failure", FailureReason: "exchange_failed"})
		s.redirectFailure(w, r, "google_exchange_failed")
		return
	}
	user, err := s.store.UpsertGoogleUser(r.Context(), identity, s.requestIP(r))
	if err != nil {
		s.recordLogin(r, LoginLog{Email: identity.Email, DisplayName: identity.Name, AuthMethod: "google", LoginResult: "failure", FailureReason: "user_upsert_failed"})
		s.redirectFailure(w, r, "google_user_failed")
		return
	}
	if !user.Enabled {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "google", LoginResult: "failure", FailureReason: "account_disabled"})
		if request.Kind == "desktop" {
			s.redirectDesktopFailure(w, r, desktopOAuthContext{CallbackURL: request.CallbackURL, DesktopState: request.DesktopState}, "account_disabled")
		} else {
			s.redirectFailure(w, r, "account_disabled")
		}
		return
	}

	authMethod := "google"
	if request.Kind == "desktop" {
		authMethod = "desktop_google"
		ticket, ticketErr := s.createDesktopSsoTicket(r, user.ID)
		if ticketErr != nil {
			s.redirectDesktopFailure(w, r, desktopOAuthContext{CallbackURL: request.CallbackURL, DesktopState: request.DesktopState}, "desktop_ticket_failed")
			return
		}
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: authMethod, LoginResult: "success"})
		s.redirectDesktopSuccess(w, r, desktopOAuthContext{CallbackURL: request.CallbackURL, DesktopState: request.DesktopState}, ticket)
		return
	}

	sessionToken, _, sessionExpiresAt, err := s.createSession(r, user.ID)
	if err != nil {
		s.redirectFailure(w, r, "google_session_failed")
		return
	}
	now := s.now().UTC()
	_ = s.store.TouchLastLogin(r.Context(), user.ID, now)
	s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: authMethod, LoginResult: "success"})
	http.SetCookie(w, s.sessionCookie(sessionToken, sessionExpiresAt))
	http.Redirect(w, r, safeRelativeRedirect(request.ReturnTo), http.StatusFound)
}

func (s *Server) desktopSsoStart(w http.ResponseWriter, r *http.Request) {
	callbackURL := strings.TrimSpace(r.URL.Query().Get("callback"))
	desktopState := strings.TrimSpace(r.URL.Query().Get("state"))
	if !isAllowedDesktopCallbackURL(callbackURL) || desktopState == "" {
		s.recordLogin(r, LoginLog{AuthMethod: s.desktopSSOAuthMethod(), LoginResult: "failure", FailureReason: "invalid_desktop_callback"})
		writeError(w, http.StatusBadRequest, "invalid_request", "Desktop callback and state are required.")
		return
	}
	desktopContext := desktopOAuthContext{
		CallbackURL:  callbackURL,
		DesktopState: desktopState,
	}

	// Compatibility path for the old nginx config that protected /start directly.
	if s.isTrustedDesktopSsoBridgeRequest(r) {
		s.completeDesktopSsoBridge(w, r, desktopContext)
		return
	}

	http.SetCookie(w, s.desktopSsoBridgeCookie(s.desktopSsoBridgeCallbackCookieName(), callbackURL))
	http.SetCookie(w, s.desktopSsoBridgeCookie(s.desktopSsoBridgeStateCookieName(), desktopState))
	if _, err := s.currentUser(r); err == nil {
		http.Redirect(w, r, "/api/auth/desktop-sso/continue", http.StatusFound)
		return
	}
	loginURL, _ := url.Parse(s.authLoginURL)
	query := loginURL.Query()
	query.Set("return_to", "/api/auth/desktop-sso/continue")
	query.Set("desktop", "1")
	loginURL.RawQuery = query.Encode()
	http.Redirect(w, r, loginURL.String(), http.StatusFound)
}

func (s *Server) desktopSsoContinue(w http.ResponseWriter, r *http.Request) {
	desktopContext, ok, err := s.readDesktopSsoBridgeContext(r)
	if !ok || err != nil {
		s.clearDesktopSsoBridgeCookies(w)
		s.recordLogin(r, LoginLog{AuthMethod: s.desktopSSOAuthMethod(), LoginResult: "failure", FailureReason: "invalid_desktop_callback"})
		writeError(w, http.StatusBadRequest, "invalid_request", "Desktop callback and state are required.")
		return
	}

	if s.isTrustedDesktopSsoBridgeRequest(r) {
		s.clearDesktopSsoBridgeCookies(w)
		s.completeDesktopSsoBridge(w, r, desktopContext)
		return
	}

	user, err := s.currentUser(r)
	if errors.Is(err, ErrNotFound) {
		loginURL, _ := url.Parse(s.authLoginURL)
		query := loginURL.Query()
		query.Set("return_to", "/api/auth/desktop-sso/continue")
		query.Set("desktop", "1")
		loginURL.RawQuery = query.Encode()
		http.Redirect(w, r, loginURL.String(), http.StatusFound)
		return
	}
	if err != nil || !user.Enabled {
		s.clearDesktopSsoBridgeCookies(w)
		s.redirectDesktopFailure(w, r, desktopContext, "account_disabled")
		return
	}
	ticket, err := s.createDesktopSsoTicket(r, user.ID)
	if err != nil {
		s.clearDesktopSsoBridgeCookies(w)
		s.redirectDesktopFailure(w, r, desktopContext, "desktop_ticket_failed")
		return
	}
	s.clearDesktopSsoBridgeCookies(w)
	s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "desktop_first_party", LoginResult: "success"})
	s.redirectDesktopSuccess(w, r, desktopContext, ticket)
}

func (s *Server) completeDesktopSsoBridge(w http.ResponseWriter, r *http.Request, desktopContext desktopOAuthContext) {
	identity := authentikIdentityFromRequest(r)
	if strings.TrimSpace(identity.Subject) == "" || !validEmail(identity.Email) {
		s.recordLogin(r, LoginLog{Email: identity.Email, DisplayName: identity.Name, AuthMethod: s.desktopSSOAuthMethod(), LoginResult: "failure", FailureReason: "missing_identity"})
		s.redirectDesktopFailure(w, r, desktopContext, "sso_missing_identity")
		return
	}

	user, err := s.store.UpsertAuthentikUser(r.Context(), identity, s.requestIP(r))
	if err != nil {
		s.recordLogin(r, LoginLog{Email: identity.Email, DisplayName: identity.Name, AuthMethod: s.desktopSSOAuthMethod(), LoginResult: "failure", FailureReason: "user_upsert_failed"})
		s.redirectDesktopFailure(w, r, desktopContext, "sso_user_failed")
		return
	}
	if !user.Enabled {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: s.desktopSSOAuthMethod(), LoginResult: "failure", FailureReason: "account_disabled"})
		s.redirectDesktopFailure(w, r, desktopContext, "account_disabled")
		return
	}

	ticket, err := s.createDesktopSsoTicket(r, user.ID)
	if err != nil {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: s.desktopSSOAuthMethod(), LoginResult: "failure", FailureReason: "ticket_create_failed"})
		s.redirectDesktopFailure(w, r, desktopContext, "desktop_ticket_failed")
		return
	}

	s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: s.desktopSSOAuthMethod(), LoginResult: "success"})
	s.redirectDesktopSuccess(w, r, desktopContext, ticket)
}

func (s *Server) desktopSsoSession(w http.ResponseWriter, r *http.Request) {
	if !s.requireValidOrigin(w, r) {
		return
	}
	var req desktopSsoSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid desktop SSO request.")
		return
	}
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	idToken := strings.TrimSpace(req.IDToken)
	ticket := strings.TrimSpace(req.Ticket)
	if ticket != "" {
		s.desktopSsoTicketSession(w, r, ticket)
		return
	}
	if provider != "google" {
		writeError(w, http.StatusBadRequest, "invalid_request", "Desktop SSO provider is required.")
		return
	}
	if !s.google.Configured() {
		writeError(w, http.StatusServiceUnavailable, "google_not_configured", "Google login is not configured.")
		return
	}
	if idToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "Desktop SSO id_token or ticket is required.")
		return
	}

	identity, err := s.google.VerifyIDToken(r.Context(), idToken)
	if err != nil {
		s.recordLogin(r, LoginLog{AuthMethod: "desktop_google", LoginResult: "failure", FailureReason: "invalid_token"})
		writeError(w, http.StatusUnauthorized, "invalid_token", "Desktop SSO token is invalid.")
		return
	}

	user, err := s.store.UpsertGoogleUser(r.Context(), identity, s.requestIP(r))
	if err != nil {
		s.recordLogin(r, LoginLog{Email: identity.Email, DisplayName: identity.Name, AuthMethod: "desktop_google", LoginResult: "failure", FailureReason: "user_upsert_failed"})
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to save user account.")
		return
	}
	if !user.Enabled {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "desktop_google", LoginResult: "failure", FailureReason: "account_disabled"})
		writeError(w, http.StatusForbidden, "account_disabled", "This account is disabled.")
		return
	}

	s.writeDesktopSsoSessionResponse(w, r, user, "desktop_google")
}

func (s *Server) desktopSsoTicketSession(w http.ResponseWriter, r *http.Request, ticket string) {
	authMethod := s.desktopSSOAuthMethod()
	user, err := s.store.ConsumeDesktopSsoTicket(r.Context(), tokenHash(ticket), s.now().UTC())
	if errors.Is(err, ErrNotFound) {
		s.recordLogin(r, LoginLog{AuthMethod: authMethod, LoginResult: "failure", FailureReason: "invalid_ticket"})
		writeError(w, http.StatusUnauthorized, "invalid_ticket", "Desktop SSO ticket is invalid or expired.")
		return
	}
	if errors.Is(err, ErrDisabledUser) {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: authMethod, LoginResult: "failure", FailureReason: "account_disabled"})
		writeError(w, http.StatusForbidden, "account_disabled", "This account is disabled.")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to read desktop SSO ticket.")
		return
	}

	s.writeDesktopSsoSessionResponse(w, r, user, authMethod)
}

func (s *Server) writeDesktopSsoSessionResponse(w http.ResponseWriter, r *http.Request, user User, authMethod string) {
	sessionToken, _, sessionExpiresAt, err := s.createSession(r, user.ID)
	if err != nil {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: authMethod, LoginResult: "failure", FailureReason: "session_create_failed"})
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to save session.")
		return
	}

	now := s.now().UTC()
	_ = s.store.TouchLastLogin(r.Context(), user.ID, now)
	user.LastLoginAt = &now
	s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: authMethod, LoginResult: "success"})

	http.SetCookie(w, s.sessionCookie(sessionToken, sessionExpiresAt))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"user":      s.publicUser(user),
		"expiresAt": sessionExpiresAt,
	})
}

func (s *Server) desktopSsoToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireCSRF(w, r) {
		return
	}
	user, err := s.currentUser(r)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Login required.")
		return
	}
	if err != nil {
		writeError(w, http.StatusForbidden, "account_disabled", "This account is disabled.")
		return
	}
	sessionToken, err := s.sessionToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Login required.")
		return
	}
	tokenUser := user
	tokenUser.AvatarURL = s.avatarProxy.publicURL(user)
	jwtToken, err := s.desktopJWTSigner.issue(tokenUser, s.now(), tokenHash(sessionToken))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "sso_jwt_not_configured", "Desktop SSO JWT signer is not configured.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"user":        s.publicUser(user),
		"accessToken": jwtToken.Token,
		"tokenType":   "Bearer",
		"expiresAt":   jwtToken.ExpiresAt,
		"issuer":      jwtToken.Issuer,
		"audience":    jwtToken.Audiences,
		"scope":       jwtToken.Scope,
	})
}

func (s *Server) csrf(w http.ResponseWriter, r *http.Request) {
	sessionToken, err := s.sessionToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Login required.")
		return
	}
	csrfToken, err := s.store.FindSessionCSRF(r.Context(), tokenHash(sessionToken), s.now().UTC())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Session is invalid or expired.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"csrfToken": csrfToken})
}

func (s *Server) authentikSsoSession(w http.ResponseWriter, r *http.Request) {
	if s.ssoBridgeToken == "" || strings.TrimSpace(r.Header.Get("X-ZenMind-SSO-Bridge-Token")) != s.ssoBridgeToken {
		s.recordLogin(r, LoginLog{AuthMethod: "authentik", LoginResult: "failure", FailureReason: "untrusted_bridge"})
		s.redirectFailure(w, r, "sso_untrusted_bridge")
		return
	}

	identity := authentikIdentityFromRequest(r)
	if strings.TrimSpace(identity.Subject) == "" || !validEmail(identity.Email) {
		s.recordLogin(r, LoginLog{Email: identity.Email, DisplayName: identity.Name, AuthMethod: "authentik", LoginResult: "failure", FailureReason: "missing_identity"})
		s.redirectFailure(w, r, "sso_missing_identity")
		return
	}

	user, err := s.store.UpsertAuthentikUser(r.Context(), identity, s.requestIP(r))
	if err != nil {
		s.recordLogin(r, LoginLog{Email: identity.Email, DisplayName: identity.Name, AuthMethod: "authentik", LoginResult: "failure", FailureReason: "user_upsert_failed"})
		s.redirectFailure(w, r, "sso_user_failed")
		return
	}
	if !user.Enabled {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "authentik", LoginResult: "failure", FailureReason: "account_disabled"})
		s.redirectFailure(w, r, "account_disabled")
		return
	}

	token, _, expiresAt, err := s.createSession(r, user.ID)
	if err != nil {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "authentik", LoginResult: "failure", FailureReason: "session_create_failed"})
		s.redirectFailure(w, r, "sso_session_failed")
		return
	}

	now := s.now().UTC()
	_ = s.store.TouchLastLogin(r.Context(), user.ID, now)
	s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "authentik", LoginResult: "success"})

	http.SetCookie(w, s.sessionCookie(token, expiresAt))
	http.Redirect(w, r, safeRelativeRedirect(r.URL.Query().Get("rd")), http.StatusFound)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user, err := s.currentUser(r)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Login required.")
		return
	}
	if errors.Is(err, ErrDisabledUser) {
		writeError(w, http.StatusForbidden, "account_disabled", "This account is disabled.")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to read session.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": s.publicUser(user)})
}

func (s *Server) avatar(w http.ResponseWriter, r *http.Request) {
	user, err := s.currentUser(r)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Login required.")
		return
	}
	if errors.Is(err, ErrDisabledUser) {
		writeError(w, http.StatusForbidden, "account_disabled", "This account is disabled.")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to read session.")
		return
	}
	s.avatarProxy.serve(w, r, user, strings.TrimSpace(r.PathValue("version")))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if _, err := s.sessionToken(r); err == nil && !s.requireCSRF(w, r) {
		return
	}
	cookie, err := r.Cookie(s.cookieName)
	if err == nil && cookie.Value != "" {
		_ = s.store.RevokeSession(r.Context(), tokenHash(cookie.Value))
	}
	http.SetCookie(w, s.expiredCookie())
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) currentUser(r *http.Request) (User, error) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil || cookie.Value == "" {
		return User{}, ErrNotFound
	}
	return s.store.FindUserBySession(r.Context(), tokenHash(cookie.Value), s.now().UTC())
}

func bearerTokenFromRequest(r *http.Request) string {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if authorization == "" {
		return ""
	}
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func authentikIdentityFromRequest(r *http.Request) AuthentikIdentity {
	username := headerFirst(r, "X-Authentik-Username")
	email := normalizeEmail(headerFirst(r, "X-Authentik-Email"))
	if email == "" && validEmail(username) {
		email = normalizeEmail(username)
	}
	return AuthentikIdentity{
		Subject:  headerFirst(r, "X-Authentik-Uid", "X-Authentik-Subject", "X-Authentik-User-Id"),
		Email:    email,
		Name:     headerFirst(r, "X-Authentik-Name"),
		Username: username,
		Picture:  headerFirst(r, "X-Authentik-Picture", "X-Authentik-Avatar"),
	}
}

func headerFirst(r *http.Request, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func safeRelativeRedirect(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\r\n\\") {
		return "/"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") {
		return "/"
	}
	return parsed.String()
}

func (s *Server) marketProxy(w http.ResponseWriter, r *http.Request) {
	if s.marketServerURL == "" || !s.desktopJWTSigner.configured() {
		writeError(w, http.StatusServiceUnavailable, "market_not_configured", "Market proxy is not configured.")
		return
	}
	target, err := url.Parse(s.marketServerURL)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "market_not_configured", "Market server URL is invalid.")
		return
	}

	var gatewayToken string
	user, userErr := s.currentUser(r)
	if userErr == nil {
		if isUnsafeMethod(r.Method) && !s.requireCSRF(w, r) {
			return
		}
		sessionToken, _ := s.sessionToken(r)
		tokenUser := user
		tokenUser.AvatarURL = s.avatarProxy.publicURL(user)
		jwtToken, signErr := s.desktopJWTSigner.issueWithPolicy(
			tokenUser,
			s.now(),
			tokenHash(sessionToken),
			[]string{s.marketJWTAudience},
			"market",
			s.marketJWTTTL,
		)
		if signErr != nil {
			writeError(w, http.StatusServiceUnavailable, "market_not_configured", "Market proxy is not configured.")
			return
		}
		gatewayToken = jwtToken.Token
	} else if !errors.Is(userErr, ErrNotFound) {
		writeError(w, http.StatusForbidden, "account_disabled", "This account is disabled.")
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		suffix := strings.TrimPrefix(r.URL.Path, "/api/market")
		if suffix == "" {
			suffix = "/"
		}
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, "/api"+suffix)
		req.URL.RawQuery = r.URL.RawQuery
		req.Host = target.Host
		stripIdentityHeaders(req.Header)
		req.Header.Del("Cookie")
		if gatewayToken != "" {
			req.Header.Set("Authorization", "Bearer "+gatewayToken)
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, proxyErr error) {
		_ = proxyErr
		writeError(w, http.StatusBadGateway, "market_proxy_failed", "Market service is unavailable.")
	}
	proxy.ServeHTTP(w, r)
}

func stripIdentityHeaders(header http.Header) {
	header.Del("Authorization")
	header.Del("X-ZenMind-User-ID")
	header.Del("X-ZenMind-User-Email")
	header.Del("X-ZenMind-User-Role")
	header.Del("X-ZenMind-Market-Proxy-Token")
	header.Del("X-Forwarded-User")
	header.Del("X-Forwarded-Email")
	header.Del("X-Forwarded-Groups")
	header.Del("X-Authentik-Username")
	header.Del("X-Authentik-Email")
	header.Del("X-Authentik-Name")
	header.Del("X-Authentik-Uid")
}

func isUnsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func (s *Server) createSession(r *http.Request, userID int64) (string, string, time.Time, error) {
	token, err := randomToken()
	if err != nil {
		return "", "", time.Time{}, err
	}
	csrfToken, err := randomToken()
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiresAt := s.now().UTC().Add(s.sessionTTL)
	if err := s.store.CreateSession(r.Context(), userID, tokenHash(token), csrfToken, expiresAt, r.UserAgent(), s.requestIP(r)); err != nil {
		return "", "", time.Time{}, err
	}
	return token, csrfToken, expiresAt, nil
}

func (s *Server) createDesktopSsoTicket(r *http.Request, userID int64) (string, error) {
	ticket, err := randomToken()
	if err != nil {
		return "", err
	}
	expiresAt := s.now().UTC().Add(s.desktopTicketTTL)
	if err := s.store.SaveDesktopSsoTicket(r.Context(), userID, tokenHash(ticket), expiresAt, s.requestIP(r), r.UserAgent()); err != nil {
		return "", err
	}
	return ticket, nil
}

func normalizeDesktopSSOProvider(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "first_party"
	}
	value = strings.Map(func(ch rune) rune {
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' {
			return ch
		}
		return -1
	}, value)
	if value == "" {
		return "first_party"
	}
	return value
}

func (s *Server) desktopSSOAuthMethod() string {
	return "desktop_" + normalizeDesktopSSOProvider(s.desktopSSOProvider)
}

func (s *Server) isTrustedDesktopSsoBridgeRequest(r *http.Request) bool {
	return s.ssoBridgeToken != "" && strings.TrimSpace(r.Header.Get("X-ZenMind-SSO-Bridge-Token")) == s.ssoBridgeToken
}

func (s *Server) sessionCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (s *Server) expiredCookie() *http.Cookie {
	return s.expiredNamedCookie(s.cookieName)
}

func (s *Server) expiredNamedCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func singleJoiningSlash(left, right string) string {
	leftSlash := strings.HasSuffix(left, "/")
	rightSlash := strings.HasPrefix(right, "/")
	switch {
	case leftSlash && rightSlash:
		return left + right[1:]
	case !leftSlash && !rightSlash:
		return left + "/" + right
	default:
		return left + right
	}
}

func (s *Server) publicUser(user User) map[string]any {
	return map[string]any{
		"id":           user.ID,
		"email":        user.Email,
		"role":         user.Role,
		"enabled":      user.Enabled,
		"displayName":  user.DisplayName,
		"avatarUrl":    s.avatarProxy.publicURL(user),
		"authProvider": user.AuthProvider,
		"lastLoginAt":  user.LastLoginAt,
	}
}

func (s *Server) oauthStateCookieName() string {
	return s.cookieName + "_oauth_state"
}

func (s *Server) oauthStateCookie(state string) *http.Cookie {
	return &http.Cookie{
		Name:     s.oauthStateCookieName(),
		Value:    state,
		Path:     "/",
		Expires:  s.now().UTC().Add(10 * time.Minute),
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (s *Server) desktopOAuthStateCookieName() string {
	return s.cookieName + "_desktop_oauth_state"
}

func (s *Server) desktopOAuthCallbackCookieName() string {
	return s.cookieName + "_desktop_oauth_callback"
}

func (s *Server) desktopOAuthDesktopStateCookieName() string {
	return s.cookieName + "_desktop_state"
}

func (s *Server) desktopOAuthCookie(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  s.now().UTC().Add(10 * time.Minute),
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (s *Server) desktopSsoBridgeCallbackCookieName() string {
	return s.cookieName + "_desktop_sso_bridge_callback"
}

func (s *Server) desktopSsoBridgeStateCookieName() string {
	return s.cookieName + "_desktop_sso_bridge_state"
}

func (s *Server) desktopSsoBridgeCookie(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  s.now().UTC().Add(10 * time.Minute),
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (s *Server) clearDesktopSsoBridgeCookies(w http.ResponseWriter) {
	http.SetCookie(w, s.expiredNamedCookie(s.desktopSsoBridgeCallbackCookieName()))
	http.SetCookie(w, s.expiredNamedCookie(s.desktopSsoBridgeStateCookieName()))
}

func (s *Server) readDesktopSsoBridgeContext(r *http.Request) (desktopOAuthContext, bool, error) {
	callbackCookie, callbackErr := r.Cookie(s.desktopSsoBridgeCallbackCookieName())
	desktopStateCookie, desktopStateErr := r.Cookie(s.desktopSsoBridgeStateCookieName())
	if callbackErr != nil && desktopStateErr != nil {
		return desktopOAuthContext{}, false, nil
	}
	if callbackErr != nil || desktopStateErr != nil {
		return desktopOAuthContext{}, true, fmt.Errorf("missing desktop sso bridge cookie")
	}
	context := desktopOAuthContext{
		CallbackURL:  strings.TrimSpace(callbackCookie.Value),
		DesktopState: strings.TrimSpace(desktopStateCookie.Value),
	}
	if context.DesktopState == "" || !isAllowedDesktopCallbackURL(context.CallbackURL) {
		return desktopOAuthContext{}, true, fmt.Errorf("invalid desktop sso bridge cookie")
	}
	return context, true, nil
}

func (s *Server) clearDesktopOAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, s.expiredNamedCookie(s.desktopOAuthStateCookieName()))
	http.SetCookie(w, s.expiredNamedCookie(s.desktopOAuthCallbackCookieName()))
	http.SetCookie(w, s.expiredNamedCookie(s.desktopOAuthDesktopStateCookieName()))
}

func (s *Server) readDesktopOAuthContext(r *http.Request) (desktopOAuthContext, bool, error) {
	oauthStateCookie, oauthStateErr := r.Cookie(s.desktopOAuthStateCookieName())
	callbackCookie, callbackErr := r.Cookie(s.desktopOAuthCallbackCookieName())
	desktopStateCookie, desktopStateErr := r.Cookie(s.desktopOAuthDesktopStateCookieName())
	if oauthStateErr != nil && callbackErr != nil && desktopStateErr != nil {
		return desktopOAuthContext{}, false, nil
	}
	if oauthStateErr != nil || callbackErr != nil || desktopStateErr != nil {
		return desktopOAuthContext{}, true, fmt.Errorf("missing desktop oauth cookie")
	}
	context := desktopOAuthContext{
		OAuthState:   strings.TrimSpace(oauthStateCookie.Value),
		CallbackURL:  strings.TrimSpace(callbackCookie.Value),
		DesktopState: strings.TrimSpace(desktopStateCookie.Value),
	}
	if context.OAuthState == "" || context.DesktopState == "" || !isAllowedDesktopCallbackURL(context.CallbackURL) {
		return desktopOAuthContext{}, true, fmt.Errorf("invalid desktop oauth cookie")
	}
	return context, true, nil
}

func isAllowedDesktopCallbackURL(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	hostname := strings.ToLower(parsed.Hostname())
	if parsed.Scheme != "http" || (hostname != "127.0.0.1" && hostname != "localhost") || parsed.Port() == "" {
		return false
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port <= 0 || port > 65535 {
		return false
	}
	if parsed.Path != "/api/auth/oidc/callback" {
		return false
	}
	return parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func buildDesktopCallbackURL(desktopContext desktopOAuthContext, values map[string]string) string {
	target, err := url.Parse(desktopContext.CallbackURL)
	if err != nil {
		return desktopContext.CallbackURL
	}
	query := target.Query()
	query.Set("state", desktopContext.DesktopState)
	for key, value := range values {
		if strings.TrimSpace(value) != "" {
			query.Set(key, value)
		}
	}
	target.RawQuery = query.Encode()
	return target.String()
}

func (s *Server) redirectDesktopSuccess(w http.ResponseWriter, r *http.Request, desktopContext desktopOAuthContext, ticket string) {
	http.Redirect(w, r, buildDesktopCallbackURL(desktopContext, map[string]string{"ticket": ticket}), http.StatusFound)
}

func (s *Server) redirectDesktopFailure(w http.ResponseWriter, r *http.Request, desktopContext desktopOAuthContext, reason string) {
	http.Redirect(w, r, buildDesktopCallbackURL(desktopContext, map[string]string{"error": reason}), http.StatusFound)
}

func (s *Server) successURL() string {
	if s.authSuccessURL != "" {
		return s.authSuccessURL
	}
	return "/login"
}

func (s *Server) failureURL(reason string) string {
	target := s.authFailureURL
	if target == "" {
		target = "/login"
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	query := parsed.Query()
	query.Set("error", reason)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (s *Server) redirectFailure(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, s.failureURL(reason), http.StatusFound)
}

func (s *Server) recordLogin(r *http.Request, entry LoginLog) {
	entry.IP = s.requestIP(r)
	entry.UserAgent = r.UserAgent()
	entry.LoginAt = s.now().UTC()
	_ = s.store.RecordLogin(r.Context(), entry)
}

func downloadEventFromRequest(r *http.Request, installerKey, version string, downloadedAt time.Time) DownloadEvent {
	return DownloadEvent{
		InstallerKey:   installerKey,
		Version:        version,
		ClientIP:       validRemoteIP(r.RemoteAddr),
		RemoteAddr:     strings.TrimSpace(r.RemoteAddr),
		XForwardedFor:  strings.TrimSpace(r.Header.Get("X-Forwarded-For")),
		XRealIP:        strings.TrimSpace(r.Header.Get("X-Real-IP")),
		UserAgent:      r.UserAgent(),
		Referer:        strings.TrimSpace(r.Referer()),
		AcceptLanguage: strings.TrimSpace(r.Header.Get("Accept-Language")),
		DownloadedAt:   downloadedAt,
	}
}

func firstValidForwardedIP(value string) string {
	for _, part := range strings.Split(value, ",") {
		if ip := validHeaderIP(part); ip != "" {
			return ip
		}
	}
	return ""
}

func validHeaderIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return ""
	}
	return addr.String()
}

func randomToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:]), nil
}

func randomDigits(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid code length")
	}
	var builder strings.Builder
	builder.Grow(length)
	for builder.Len() < length {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		if b[0] > 249 {
			continue
		}
		builder.WriteString(strconv.Itoa(int(b[0] % 10)))
	}
	return builder.String(), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func pkceChallenge(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func emailCodeHash(email, code string) string {
	sum := sha256.Sum256([]byte(normalizeEmail(email) + ":" + strings.TrimSpace(code)))
	return hex.EncodeToString(sum[:])
}

func validEmail(email string) bool {
	return len(email) <= 255 && emailPattern.MatchString(email)
}

func validEmailCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
