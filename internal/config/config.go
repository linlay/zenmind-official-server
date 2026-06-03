package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr              string
	DatabaseURL       string
	InitAdminEmail    string
	InitAdminPassword string
	CookieName        string
	CookieSecure      bool
	SessionTTL        time.Duration
	GoogleClientID    string
	GoogleSecret      string
	GoogleRedirectURL string
	AuthSuccessURL    string
	AuthFailureURL    string
}

func FromEnv() (Config, error) {
	cfg := Config{
		Addr:              env("APP_ADDR", ":8080"),
		CookieName:        env("COOKIE_NAME", "zenmind_session"),
		CookieSecure:      envBool("COOKIE_SECURE", false),
		SessionTTL:        envDuration("SESSION_TTL", 24*time.Hour),
		GoogleClientID:    os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleSecret:      os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL: os.Getenv("GOOGLE_REDIRECT_URL"),
		AuthSuccessURL:    env("AUTH_SUCCESS_URL", "http://localhost:5173/login"),
		AuthFailureURL:    env("AUTH_FAILURE_URL", "http://localhost:5173/login"),
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
