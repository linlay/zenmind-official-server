package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteDownloadStoreRecordsEventAndStats(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLiteDownloadStore(ctx, filepath.Join(t.TempDir(), "data.sqlite"))
	if err != nil {
		t.Fatalf("open sqlite download store: %v", err)
	}
	defer store.Close()
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}

	downloadedAt := time.Date(2026, 6, 15, 10, 11, 12, 0, time.UTC)
	event := DownloadEvent{
		InstallerKey:   "mac",
		Version:        "0.2.4",
		ClientIP:       "203.0.113.8",
		RemoteAddr:     "172.18.0.2:54321",
		XForwardedFor:  "203.0.113.8, 10.0.0.2",
		XRealIP:        "198.51.100.7",
		UserAgent:      "Mozilla/5.0 ZenMind Test",
		Referer:        "https://zenmind.cc/download",
		AcceptLanguage: "zh-CN,zh;q=0.9",
		DownloadedAt:   downloadedAt,
	}
	if err := store.RecordDownloadEvent(ctx, event); err != nil {
		t.Fatalf("record first download: %v", err)
	}
	if err := store.RecordDownloadEvent(ctx, event); err != nil {
		t.Fatalf("record second download: %v", err)
	}

	stats, err := store.ListDownloadStats(ctx)
	if err != nil {
		t.Fatalf("list stats: %v", err)
	}
	if len(stats) != 1 || stats[0].InstallerKey != "mac" || stats[0].Total != 2 {
		t.Fatalf("unexpected stats: %#v", stats)
	}

	var got DownloadEvent
	var downloadedAtText string
	row := store.db.QueryRowContext(ctx, `SELECT
		INSTALLER_KEY_,
		VERSION_,
		CLIENT_IP_,
		REMOTE_ADDR_,
		X_FORWARDED_FOR_,
		X_REAL_IP_,
		USER_AGENT_,
		REFERER_,
		ACCEPT_LANGUAGE_,
		DOWNLOADED_AT_
		FROM download
		ORDER BY ID_
		LIMIT 1`)
	if err := row.Scan(
		&got.InstallerKey,
		&got.Version,
		&got.ClientIP,
		&got.RemoteAddr,
		&got.XForwardedFor,
		&got.XRealIP,
		&got.UserAgent,
		&got.Referer,
		&got.AcceptLanguage,
		&downloadedAtText,
	); err != nil {
		t.Fatalf("scan download row: %v", err)
	}
	got.DownloadedAt, err = time.Parse(time.RFC3339Nano, downloadedAtText)
	if err != nil {
		t.Fatalf("parse downloaded_at: %v", err)
	}

	if got.InstallerKey != event.InstallerKey ||
		got.Version != event.Version ||
		got.ClientIP != event.ClientIP ||
		got.RemoteAddr != event.RemoteAddr ||
		got.XForwardedFor != event.XForwardedFor ||
		got.XRealIP != event.XRealIP ||
		got.UserAgent != event.UserAgent ||
		got.Referer != event.Referer ||
		got.AcceptLanguage != event.AcceptLanguage ||
		!got.DownloadedAt.Equal(downloadedAt) {
		t.Fatalf("unexpected download row: %#v", got)
	}
}
