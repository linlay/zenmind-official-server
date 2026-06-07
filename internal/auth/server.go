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
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	store          Store
	cookieName     string
	cookieSecure   bool
	sessionTTL     time.Duration
	google         GoogleProvider
	authSuccessURL string
	authFailureURL string
	mailer         Mailer
	now            func() time.Time
}

type ServerOptions struct {
	CookieName     string
	CookieSecure   bool
	SessionTTL     time.Duration
	Google         GoogleProvider
	AuthSuccessURL string
	AuthFailureURL string
	Mailer         Mailer
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
	google := opts.Google
	if google == nil {
		google = disabledGoogleProvider{}
	}
	mailer := opts.Mailer
	if mailer == nil {
		mailer = disabledMailer{}
	}

	return &Server{
		store:          store,
		cookieName:     cookieName,
		cookieSecure:   opts.CookieSecure,
		sessionTTL:     sessionTTL,
		google:         google,
		authSuccessURL: strings.TrimSpace(opts.AuthSuccessURL),
		authFailureURL: strings.TrimSpace(opts.AuthFailureURL),
		mailer:         mailer,
		now:            time.Now,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/downloads/stats", s.downloadStats)
	mux.HandleFunc("POST /api/downloads/events", s.downloadEvent)
	mux.HandleFunc("POST /api/auth/login", s.login)
	mux.HandleFunc("POST /api/auth/email-code/start", s.emailCodeStart)
	mux.HandleFunc("POST /api/auth/email-code/verify", s.emailCodeVerify)
	mux.HandleFunc("GET /api/auth/google/start", s.googleStart)
	mux.HandleFunc("GET /api/auth/google/callback", s.googleCallback)
	mux.HandleFunc("GET /api/v1/auth/google/callback", s.googleCallback)
	mux.HandleFunc("POST /api/auth/desktop-sso/session", s.desktopSsoSession)
	mux.HandleFunc("GET /api/auth/me", s.me)
	mux.HandleFunc("POST /api/auth/logout", s.logout)
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
}

type desktopSsoSessionRequest struct {
	Provider string `json:"provider"`
	IDToken  string `json:"id_token"`
}

var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

var allowedInstallerKeys = map[string]bool{
	"mac":     true,
	"windows": true,
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid login request.")
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

	token, expiresAt, err := s.createSession(r, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to save session.")
		return
	}
	now := s.now().UTC()
	_ = s.store.TouchLastLogin(r.Context(), user.ID, now)
	user.LastLoginAt = &now
	s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "local", LoginResult: "success"})

	http.SetCookie(w, s.sessionCookie(token, expiresAt))
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(user)})
}

func (s *Server) emailCodeStart(w http.ResponseWriter, r *http.Request) {
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
	var req emailCodeVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid verification request.")
		return
	}
	email := normalizeEmail(req.Email)
	code := strings.TrimSpace(req.Code)
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

	user, err := s.store.UpsertEmailCodeUser(r.Context(), email, requestIP(r))
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

	token, expiresAt, err := s.createSession(r, user.ID)
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
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(user)})
}

func (s *Server) downloadStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.ListDownloadStats(r.Context())
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

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.store.IncrementDownloadCount(ctx, installerKey)
	}()

	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

func (s *Server) googleStart(w http.ResponseWriter, r *http.Request) {
	if !s.google.Configured() {
		s.redirectFailure(w, r, "google_not_configured")
		return
	}

	state, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to start Google login.")
		return
	}

	http.SetCookie(w, s.oauthStateCookie(state))
	http.Redirect(w, r, s.google.AuthCodeURL(state), http.StatusFound)
}

func (s *Server) googleCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie(s.oauthStateCookieName())
	if err != nil || stateCookie.Value == "" {
		s.recordLogin(r, LoginLog{AuthMethod: "google", LoginResult: "failure", FailureReason: "missing_state"})
		s.redirectFailure(w, r, "missing_state")
		return
	}
	if stateCookie.Value != r.URL.Query().Get("state") {
		http.SetCookie(w, s.expiredNamedCookie(s.oauthStateCookieName()))
		s.recordLogin(r, LoginLog{AuthMethod: "google", LoginResult: "failure", FailureReason: "invalid_state"})
		s.redirectFailure(w, r, "invalid_state")
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		http.SetCookie(w, s.expiredNamedCookie(s.oauthStateCookieName()))
		s.recordLogin(r, LoginLog{AuthMethod: "google", LoginResult: "failure", FailureReason: "missing_code"})
		s.redirectFailure(w, r, "missing_code")
		return
	}

	identity, err := s.google.ExchangeCode(r.Context(), code)
	if err != nil {
		http.SetCookie(w, s.expiredNamedCookie(s.oauthStateCookieName()))
		s.recordLogin(r, LoginLog{AuthMethod: "google", LoginResult: "failure", FailureReason: "exchange_failed"})
		s.redirectFailure(w, r, "google_exchange_failed")
		return
	}

	user, err := s.store.UpsertGoogleUser(r.Context(), identity, requestIP(r))
	if err != nil {
		http.SetCookie(w, s.expiredNamedCookie(s.oauthStateCookieName()))
		s.recordLogin(r, LoginLog{Email: identity.Email, DisplayName: identity.Name, AuthMethod: "google", LoginResult: "failure", FailureReason: "user_upsert_failed"})
		s.redirectFailure(w, r, "google_user_failed")
		return
	}
	if !user.Enabled {
		http.SetCookie(w, s.expiredNamedCookie(s.oauthStateCookieName()))
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "google", LoginResult: "failure", FailureReason: "account_disabled"})
		s.redirectFailure(w, r, "account_disabled")
		return
	}

	token, expiresAt, err := s.createSession(r, user.ID)
	if err != nil {
		http.SetCookie(w, s.expiredNamedCookie(s.oauthStateCookieName()))
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "google", LoginResult: "failure", FailureReason: "session_create_failed"})
		s.redirectFailure(w, r, "google_session_failed")
		return
	}

	now := s.now().UTC()
	_ = s.store.TouchLastLogin(r.Context(), user.ID, now)
	s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "google", LoginResult: "success"})

	http.SetCookie(w, s.expiredNamedCookie(s.oauthStateCookieName()))
	http.SetCookie(w, s.sessionCookie(token, expiresAt))
	http.Redirect(w, r, s.successURL(), http.StatusFound)
}

func (s *Server) desktopSsoSession(w http.ResponseWriter, r *http.Request) {
	if !s.google.Configured() {
		writeError(w, http.StatusServiceUnavailable, "google_not_configured", "Google login is not configured.")
		return
	}

	var req desktopSsoSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid desktop SSO request.")
		return
	}
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	idToken := strings.TrimSpace(req.IDToken)
	if provider != "google" || idToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "Desktop SSO provider and id_token are required.")
		return
	}

	identity, err := s.google.VerifyIDToken(r.Context(), idToken)
	if err != nil {
		s.recordLogin(r, LoginLog{AuthMethod: "desktop_google", LoginResult: "failure", FailureReason: "invalid_token"})
		writeError(w, http.StatusUnauthorized, "invalid_token", "Desktop SSO token is invalid.")
		return
	}

	user, err := s.store.UpsertGoogleUser(r.Context(), identity, requestIP(r))
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

	token, expiresAt, err := s.createSession(r, user.ID)
	if err != nil {
		s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "desktop_google", LoginResult: "failure", FailureReason: "session_create_failed"})
		writeError(w, http.StatusInternalServerError, "server_error", "Unable to save session.")
		return
	}

	now := s.now().UTC()
	_ = s.store.TouchLastLogin(r.Context(), user.ID, now)
	user.LastLoginAt = &now
	s.recordLogin(r, LoginLog{UserID: &user.ID, Email: user.Email, DisplayName: user.DisplayName, AuthMethod: "desktop_google", LoginResult: "success"})

	http.SetCookie(w, s.sessionCookie(token, expiresAt))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": publicUser(user)})
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
	writeJSON(w, http.StatusOK, map[string]any{"user": publicUser(user)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) createSession(r *http.Request, userID int64) (string, time.Time, error) {
	token, err := randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := s.now().UTC().Add(s.sessionTTL)
	if err := s.store.CreateSession(r.Context(), userID, tokenHash(token), expiresAt, r.UserAgent(), requestIP(r)); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
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

func publicUser(user User) map[string]any {
	return map[string]any{
		"id":           user.ID,
		"email":        user.Email,
		"role":         user.Role,
		"enabled":      user.Enabled,
		"displayName":  user.DisplayName,
		"avatarUrl":    user.AvatarURL,
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
	entry.IP = requestIP(r)
	entry.UserAgent = r.UserAgent()
	entry.LoginAt = s.now().UTC()
	_ = s.store.RecordLogin(r.Context(), entry)
}

func requestIP(r *http.Request) string {
	for _, header := range []string{"X-Forwarded-For", "X-Real-IP"} {
		value := strings.TrimSpace(r.Header.Get(header))
		if value == "" {
			continue
		}
		if first, _, ok := strings.Cut(value, ","); ok {
			return strings.TrimSpace(first)
		}
		return value
	}
	return strings.TrimSpace(r.RemoteAddr)
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
