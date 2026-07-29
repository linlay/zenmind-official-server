package auth

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

type rateLimitEntry struct {
	count       int
	windowStart time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateLimitEntry
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{entries: map[string]rateLimitEntry{}}
}

func (l *rateLimiter) allow(key string, limit int, window time.Duration, now time.Time) bool {
	if l == nil || key == "" || limit <= 0 || window <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) > 10_000 {
		for entryKey, entry := range l.entries {
			if now.Sub(entry.windowStart) >= 30*time.Minute {
				delete(l.entries, entryKey)
			}
		}
	}
	entry := l.entries[key]
	if entry.windowStart.IsZero() || now.Sub(entry.windowStart) >= window {
		l.entries[key] = rateLimitEntry{count: 1, windowStart: now}
		return true
	}
	if entry.count >= limit {
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}

func parseTrustedProxyCIDRs(values []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes
}

func (s *Server) requestIP(r *http.Request) string {
	remoteIP := validRemoteIP(r.RemoteAddr)
	if remoteIP == "" || !isIPInPrefixes(remoteIP, s.trustedProxyCIDRs) {
		return remoteIP
	}
	if ip := firstValidForwardedIP(r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}
	if ip := validHeaderIP(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	return remoteIP
}

func isIPInPrefixes(value string, prefixes []netip.Prefix) bool {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) sessionToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return "", ErrNotFound
	}
	return strings.TrimSpace(cookie.Value), nil
}

func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	sessionToken, err := s.sessionToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Login required.")
		return false
	}
	expected, err := s.store.FindSessionCSRF(r.Context(), tokenHash(sessionToken), s.now().UTC())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Session is invalid or expired.")
		return false
	}
	provided := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if len(expected) != len(provided) || subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) != 1 {
		writeError(w, http.StatusForbidden, "csrf_failed", "CSRF token is invalid.")
		return false
	}
	if !s.validRequestOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_failed", "Request origin is not allowed.")
		return false
	}
	return true
}

func (s *Server) requireValidOrigin(w http.ResponseWriter, r *http.Request) bool {
	if s.validRequestOrigin(r) {
		return true
	}
	writeError(w, http.StatusForbidden, "origin_failed", "Request origin is not allowed.")
	return false
}

func (s *Server) validRequestOrigin(r *http.Request) bool {
	rawOrigin := strings.TrimSpace(r.Header.Get("Origin"))
	if rawOrigin == "" {
		return true
	}
	origin, err := url.Parse(rawOrigin)
	if err != nil || origin.Scheme == "" || origin.Host == "" {
		return false
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if isIPInPrefixes(validRemoteIP(r.RemoteAddr), s.trustedProxyCIDRs) {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwarded == "http" || forwarded == "https" {
			scheme = forwarded
		}
	}
	requestOrigin := scheme + "://" + r.Host
	if strings.EqualFold(rawOrigin, requestOrigin) {
		return true
	}
	return s.authOrigin != "" && strings.EqualFold(rawOrigin, s.authOrigin)
}

func originFromURL(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func validRemoteIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		value = host
	}
	return validHeaderIP(value)
}
