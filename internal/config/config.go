package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSQLiteDBPath = "/data/data.sqlite"
	sqliteDBPathEnv     = "SQLITE_DB_PATH"
)

type Config struct {
	Addr                  string
	DatabaseURL           string
	InitAdminEmail        string
	InitAdminPassword     string
	CookieName            string
	CookieSecure          bool
	SessionTTL            time.Duration
	TrustedProxyCIDRs     []string
	GoogleClientID        string
	GoogleDesktopID       string
	GoogleSecret          string
	GoogleRedirectURL     string
	SSOBridgeToken        string
	DesktopSSOProvider    string
	DesktopSSOTicketTTL   time.Duration
	SSOJWTPrivateKeyFile  string
	SSOJWTPrivateKeyPEM   string
	SSOJWTIssuer          string
	SSOJWTAudiences       []string
	SSOJWTKeyID           string
	SSOJWTTTL             time.Duration
	MarketJWTAudience     string
	MarketJWTTTL          time.Duration
	AuthLoginURL          string
	AuthSuccessURL        string
	AuthFailureURL        string
	AuthPublicOrigin      string
	AvatarProxyEnabled    bool
	AvatarUpstreamOrigins []string
	AvatarCacheDir        string
	AvatarCacheTTL        time.Duration
	AvatarFetchTimeout    time.Duration
	AvatarMaxBytes        int64
	SMTPHost              string
	SMTPPort              string
	SMTPUsername          string
	SMTPPassword          string
	SMTPFrom              string
	MarketServerURL       string
	MarketProxyToken      string
	SQLiteDBPath          string
}

func FromEnv() (Config, error) {
	cfg := Config{
		Addr:                  env("APP_ADDR", ":8080"),
		CookieName:            env("COOKIE_NAME", "zenmind_session"),
		CookieSecure:          envBool("COOKIE_SECURE", true),
		SessionTTL:            envDuration("SESSION_TTL", 24*time.Hour),
		TrustedProxyCIDRs:     csvEnv("TRUSTED_PROXY_CIDRS", "172.20.0.0/16"),
		GoogleClientID:        os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleDesktopID:       os.Getenv("GOOGLE_DESKTOP_CLIENT_ID"),
		GoogleSecret:          os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:     os.Getenv("GOOGLE_REDIRECT_URL"),
		SSOBridgeToken:        os.Getenv("SSO_BRIDGE_TOKEN"),
		DesktopSSOProvider:    env("DESKTOP_SSO_PROVIDER", "first_party"),
		DesktopSSOTicketTTL:   envDuration("DESKTOP_SSO_TICKET_TTL", 2*time.Minute),
		SSOJWTPrivateKeyFile:  strings.TrimSpace(os.Getenv("SSO_JWT_PRIVATE_KEY_FILE")),
		SSOJWTPrivateKeyPEM:   strings.TrimSpace(os.Getenv("SSO_JWT_PRIVATE_KEY_PEM")),
		SSOJWTIssuer:          strings.TrimSpace(os.Getenv("SSO_JWT_ISSUER")),
		SSOJWTAudiences:       csvEnv("SSO_JWT_AUDIENCES", "market,tunnel,kanban,zenmind-im-server"),
		SSOJWTKeyID:           env("SSO_JWT_KEY_ID", "default"),
		SSOJWTTTL:             envDuration("SSO_JWT_TTL", 12*time.Hour),
		MarketJWTAudience:     env("MARKET_JWT_AUDIENCE", "market"),
		MarketJWTTTL:          envDuration("MARKET_JWT_TTL", 90*time.Second),
		AuthLoginURL:          env("AUTH_LOGIN_URL", "/login"),
		AuthSuccessURL:        env("AUTH_SUCCESS_URL", "http://localhost:5173/login"),
		AuthFailureURL:        env("AUTH_FAILURE_URL", "http://localhost:5173/login"),
		AuthPublicOrigin:      strings.TrimRight(strings.TrimSpace(os.Getenv("AUTH_PUBLIC_ORIGIN")), "/"),
		AvatarProxyEnabled:    envBool("AVATAR_PROXY_ENABLED", false),
		AvatarUpstreamOrigins: csvEnv("AVATAR_UPSTREAM_ORIGINS", ""),
		AvatarCacheDir:        env("AVATAR_CACHE_DIR", "/data/avatars"),
		AvatarCacheTTL:        envDuration("AVATAR_CACHE_TTL", 24*time.Hour),
		AvatarFetchTimeout:    envDuration("AVATAR_FETCH_TIMEOUT", 10*time.Second),
		AvatarMaxBytes:        envInt64("AVATAR_MAX_BYTES", 1024*1024),
		SMTPHost:              env("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:              env("SMTP_PORT", "587"),
		SMTPUsername:          env("SMTP_USERNAME", "linlay.zenmind@gmail.com"),
		SMTPPassword:          os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:              env("SMTP_FROM", "linlay.zenmind@gmail.com"),
		MarketServerURL:       strings.TrimRight(env("MARKET_SERVER_URL", "http://zenmind-market-server:8088"), "/"),
		MarketProxyToken:      os.Getenv("MARKET_PROXY_TOKEN"),
		SQLiteDBPath:          env(sqliteDBPathEnv, defaultSQLiteDBPath),
	}

	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	if cfg.DatabaseURL == "" {
		host := env("MYSQL_HOST", "mysql")
		port := env("MYSQL_PORT", "3306")
		user := env("MYSQL_USER", "zenmind")
		password := os.Getenv("MYSQL_PASSWORD")
		if password == "" {
			return cfg, errors.New("DATABASE_URL or MYSQL_PASSWORD is required")
		}
		database := env("MYSQL_DATABASE", "zenmind_website")
		cfg.DatabaseURL = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci", user, password, host, port, database)
	}

	cfg.InitAdminEmail = os.Getenv("INIT_ADMIN_EMAIL")
	cfg.InitAdminPassword = os.Getenv("INIT_ADMIN_PASSWORD")
	if cfg.InitAdminEmail == "" || cfg.InitAdminPassword == "" {
		return cfg, errors.New("INIT_ADMIN_EMAIL and INIT_ADMIN_PASSWORD are required")
	}
	if cfg.AvatarProxyEnabled {
		if !isHTTPSOrigin(cfg.AuthPublicOrigin) {
			return cfg, errors.New("AUTH_PUBLIC_ORIGIN must be an HTTPS origin when AVATAR_PROXY_ENABLED=true")
		}
		if len(cfg.AvatarUpstreamOrigins) == 0 {
			return cfg, errors.New("AVATAR_UPSTREAM_ORIGINS is required when AVATAR_PROXY_ENABLED=true")
		}
		for _, origin := range cfg.AvatarUpstreamOrigins {
			if !isHTTPSOrigin(origin) {
				return cfg, fmt.Errorf("AVATAR_UPSTREAM_ORIGINS contains an invalid HTTPS origin: %s", origin)
			}
		}
	}

	return cfg, nil
}

func isHTTPSOrigin(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	return err == nil &&
		parsed.Scheme == "https" &&
		parsed.Host != "" &&
		parsed.User == nil &&
		(parsed.Path == "" || parsed.Path == "/") &&
		parsed.RawQuery == "" &&
		parsed.Fragment == ""
}

func env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func csvEnv(key, fallback string) []string {
	value := env(key, fallback)
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		result = append(result, part)
	}
	return result
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
