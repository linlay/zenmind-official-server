package config

import (
	"testing"
	"time"
)

func TestFromEnvLoadsAvatarProxyConfiguration(t *testing.T) {
	t.Setenv("DATABASE_URL", "database")
	t.Setenv("INIT_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("INIT_ADMIN_PASSWORD", "password")
	t.Setenv("AUTH_PUBLIC_ORIGIN", "https://www.zenmind.cc/")
	t.Setenv("AVATAR_PROXY_ENABLED", "true")
	t.Setenv(
		"AVATAR_UPSTREAM_ORIGINS",
		"https://lh3.googleusercontent.com, https://images.example.com",
	)
	t.Setenv("AVATAR_CACHE_DIR", "/tmp/avatar-cache")
	t.Setenv("AVATAR_CACHE_TTL", "6h")
	t.Setenv("AVATAR_FETCH_TIMEOUT", "3s")
	t.Setenv("AVATAR_MAX_BYTES", "524288")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.AuthPublicOrigin != "https://www.zenmind.cc" {
		t.Fatalf("AuthPublicOrigin = %q", cfg.AuthPublicOrigin)
	}
	if !cfg.AvatarProxyEnabled {
		t.Fatal("AvatarProxyEnabled = false")
	}
	if len(cfg.AvatarUpstreamOrigins) != 2 ||
		cfg.AvatarUpstreamOrigins[0] != "https://lh3.googleusercontent.com" ||
		cfg.AvatarUpstreamOrigins[1] != "https://images.example.com" {
		t.Fatalf("AvatarUpstreamOrigins = %#v", cfg.AvatarUpstreamOrigins)
	}
	if cfg.AvatarCacheDir != "/tmp/avatar-cache" ||
		cfg.AvatarCacheTTL != 6*time.Hour ||
		cfg.AvatarFetchTimeout != 3*time.Second ||
		cfg.AvatarMaxBytes != 524288 {
		t.Fatalf("avatar config = %#v", cfg)
	}
}

func TestFromEnvRejectsIncompleteAvatarProxyConfiguration(t *testing.T) {
	t.Setenv("DATABASE_URL", "database")
	t.Setenv("INIT_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("INIT_ADMIN_PASSWORD", "password")
	t.Setenv("AVATAR_PROXY_ENABLED", "true")
	t.Setenv("AUTH_PUBLIC_ORIGIN", "https://www.zenmind.cc")
	t.Setenv("AVATAR_UPSTREAM_ORIGINS", "http://lh3.googleusercontent.com")

	if _, err := FromEnv(); err == nil {
		t.Fatal("FromEnv accepted an insecure avatar upstream origin")
	}
}
