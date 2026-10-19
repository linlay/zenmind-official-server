package auth

import (
	"database/sql"
	"testing"
	"time"
)

// Execute the production UPDATE against the already bundled SQLite driver.
// Both engines support the CASE/TRIM/IF expression used by this statement.
func TestIdentityProfileUpdatePreservesEmailLoginName(t *testing.T) {
	for _, tc := range []struct{ name, provider, existing, incoming, want string }{
		{"email keeps SSO name", "email_code", "x xie", "same@example.com", "x xie"},
		{"email keeps user name verbatim", "email_code", "  Custom Name  ", "same@example.com", "  Custom Name  "},
		{"email fills empty name", "email_code", "", "same@example.com", "same@example.com"},
		{"email fills whitespace name", "email_code", "   ", "same@example.com", "same@example.com"},
		{"google updates name", "google", "Old Name", "Google Name", "Google Name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			_, err = db.Exec(`CREATE TABLE auth_user (ID_ INTEGER PRIMARY KEY, EMAIL_ TEXT, DISPLAY_NAME_ TEXT, AVATAR_URL_ TEXT, UPDATED_AT_ TEXT, LAST_LOGIN_AT_ TEXT)`)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(`INSERT INTO auth_user VALUES (1, 'same@example.com', ?, 'existing-avatar', '', '')`, tc.existing)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			// Repeated email logins must preserve the same profile too.
			for i := 0; i < 2; i++ {
				_, err = db.Exec(updateIdentityUserProfileSQL, "same@example.com", tc.provider, tc.incoming, tc.incoming, "", "", now, now, 1)
				if err != nil {
					t.Fatal(err)
				}
				var name, avatar string
				if err := db.QueryRow(`SELECT DISPLAY_NAME_, AVATAR_URL_ FROM auth_user WHERE ID_ = 1`).Scan(&name, &avatar); err != nil {
					t.Fatal(err)
				}
				if name != tc.want || avatar != "existing-avatar" {
					t.Fatalf("profile = %q / %q, want %q / existing-avatar", name, avatar, tc.want)
				}
			}
		})
	}
}
