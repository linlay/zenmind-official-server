package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSQLSessionStartReadsExistingCreationTime(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE auth_session (TOKEN_HASH_ TEXT, CREATED_AT_ TIMESTAMP, EXPIRES_AT_ TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	started := now.Add(-time.Hour)
	if _, err := db.Exec(`INSERT INTO auth_session VALUES (?, ?, ?)`, "live", started, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	store := &MySQLStore{db: db}
	for _, lookupTime := range []time.Time{now, now.Add(time.Minute)} {
		actual, err := store.FindSessionStartedAt(t.Context(), "live", lookupTime)
		if err != nil || !actual.Equal(started) {
			t.Fatalf("session start=%v err=%v", actual, err)
		}
	}
	if _, err := store.FindSessionStartedAt(t.Context(), "missing", now); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing session accepted", err)
	}
	if _, err := store.FindSessionStartedAt(t.Context(), "live", now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired session accepted", err)
	}
	db.Close()
	if _, err := store.FindSessionStartedAt(t.Context(), "live", now); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("database error was hidden", err)
	}
}

func TestDesktopJWTSessionStartSurvivesTokenRenewal(t *testing.T) {
	signer := newIdentityJWTSigner(testDesktopJWTConfig(t))
	started := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	user := User{ID: 42, Enabled: true}
	for _, now := range []time.Time{started.Add(time.Minute), started.Add(30 * time.Minute)} {
		result, err := signer.issue(user, now, "same-session", started)
		if err != nil {
			t.Fatal(err)
		}
		claims := decodeTestJWTClaims(t, result.Token)
		if int64(claims["session_started_at_ms"].(float64)) != started.UnixMilli() || int64(claims["iat"].(float64)) != now.Unix() {
			t.Fatal("renewal changed the login time or failed to renew issuance time")
		}
	}
}

func TestDesktopSSOTokenReadsOriginalLoginSession(t *testing.T) {
	handler, store := testHandler(t)
	started := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	for _, item := range []struct {
		token   string
		started time.Time
	}{
		{"first-login", started}, {"second-login", started.Add(30 * time.Minute)},
	} {
		if err := store.CreateSession(context.Background(), 1, tokenHash(item.token), "csrf", time.Now().Add(time.Hour), "", ""); err != nil {
			t.Fatal(err)
		}
		record := store.sessions[tokenHash(item.token)]
		record.startedAt = item.started
		store.sessions[tokenHash(item.token)] = record
		for range 2 {
			req := httptest.NewRequest(http.MethodPost, "/api/auth/desktop-sso/token", strings.NewReader(`{}`))
			req.AddCookie(&http.Cookie{Name: "test_session", Value: item.token})
			req.Header.Set("X-CSRF-Token", "csrf")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("token: %d %s", rec.Code, rec.Body.String())
			}
			var body struct {
				AccessToken string `json:"accessToken"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			claims := decodeTestJWTClaims(t, body.AccessToken)
			if int64(claims["session_started_at_ms"].(float64)) != item.started.UnixMilli() {
				t.Fatal("token did not use the stored login time")
			}
		}
	}
}
