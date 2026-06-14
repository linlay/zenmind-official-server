package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSQLiteDBPath = "/data/data.sqlite"
	legacySQLiteDBPath  = "/data/installers.sqlite"
	sqliteDBPathEnv     = "SQLITE_DB_PATH"
	installerDBPathEnv  = "INSTALLER_DB_PATH"
)

type Config struct {
	Addr               string
	DatabaseURL        string
	InitAdminEmail     string
	InitAdminPassword  string
	CookieName         string
	CookieSecure       bool
	SessionTTL         time.Duration
	GoogleClientID     string
	GoogleDesktopID    string
	GoogleSecret       string
	GoogleRedirectURL  string
	AuthSuccessURL     string
	AuthFailureURL     string
	SMTPHost           string
	SMTPPort           string
	SMTPUsername       string
	SMTPPassword       string
	SMTPFrom           string
	MarketServerURL    string
	MarketProxyToken   string
	SQLiteDBPath       string
	SQLiteDBPathLegacy bool
}

func FromEnv() (Config, error) {
	sqliteDBPath, sqliteDBPathLegacy := resolveSQLiteDBPath()
	cfg := Config{
		Addr:               env("APP_ADDR", ":8080"),
		CookieName:         env("COOKIE_NAME", "zenmind_session"),
		CookieSecure:       envBool("COOKIE_SECURE", false),
		SessionTTL:         envDuration("SESSION_TTL", 24*time.Hour),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleDesktopID:    os.Getenv("GOOGLE_DESKTOP_CLIENT_ID"),
		GoogleSecret:       os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		AuthSuccessURL:     env("AUTH_SUCCESS_URL", "http://localhost:5173/login"),
		AuthFailureURL:     env("AUTH_FAILURE_URL", "http://localhost:5173/login"),
		SMTPHost:           env("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:           env("SMTP_PORT", "587"),
		SMTPUsername:       env("SMTP_USERNAME", "linlay.zenmind@gmail.com"),
		SMTPPassword:       os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:           env("SMTP_FROM", "linlay.zenmind@gmail.com"),
		MarketServerURL:    strings.TrimRight(env("MARKET_SERVER_URL", "http://zenmind-market-server:8088"), "/"),
		MarketProxyToken:   os.Getenv("MARKET_PROXY_TOKEN"),
		SQLiteDBPath:       sqliteDBPath,
		SQLiteDBPathLegacy: sqliteDBPathLegacy,
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

	return cfg, nil
}

func resolveSQLiteDBPath() (string, bool) {
	if value := strings.TrimSpace(os.Getenv(sqliteDBPathEnv)); value != "" {
		return filepath.Clean(value), false
	}
	if value := strings.TrimSpace(os.Getenv(installerDBPathEnv)); value != "" {
		return filepath.Clean(value), true
	}
	if fileExists(legacySQLiteDBPath) && !fileExists(defaultSQLiteDBPath) {
		return legacySQLiteDBPath, true
	}
	return defaultSQLiteDBPath, false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func env(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
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
