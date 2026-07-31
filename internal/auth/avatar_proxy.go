package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const avatarProxyMaxRedirects = 3

var avatarExtensionByContentType = map[string]string{
	"image/gif":  ".gif",
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/webp": ".webp",
}

var avatarContentTypeByExtension = map[string]string{
	".gif":  "image/gif",
	".jpg":  "image/jpeg",
	".png":  "image/png",
	".webp": "image/webp",
}

type AvatarProxyConfig struct {
	Enabled        bool
	PublicOrigin   string
	AllowedOrigins []string
	CacheDir       string
	CacheTTL       time.Duration
	FetchTimeout   time.Duration
	MaxBytes       int64
}

type avatarProxy struct {
	configured     bool
	enabled        bool
	publicOrigin   string
	allowedOrigins map[string]bool
	cacheDir       string
	cacheTTL       time.Duration
	maxBytes       int64
	httpClient     *http.Client
	locks          sync.Map
}

func newAvatarProxy(config AvatarProxyConfig) *avatarProxy {
	publicOrigin := normalizeAvatarOrigin(config.PublicOrigin)
	allowedOrigins := make(map[string]bool, len(config.AllowedOrigins))
	for _, value := range config.AllowedOrigins {
		if origin := normalizeAvatarOrigin(value); origin != "" {
			allowedOrigins[origin] = true
		}
	}
	cacheTTL := config.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 24 * time.Hour
	}
	fetchTimeout := config.FetchTimeout
	if fetchTimeout <= 0 {
		fetchTimeout = 10 * time.Second
	}
	maxBytes := config.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 1024 * 1024
	}
	cacheDir := strings.TrimSpace(config.CacheDir)
	if cacheDir == "" {
		cacheDir = "/data/avatars"
	}
	return &avatarProxy{
		configured:     config.Enabled,
		enabled:        config.Enabled && publicOrigin != "" && len(allowedOrigins) > 0,
		publicOrigin:   publicOrigin,
		allowedOrigins: allowedOrigins,
		cacheDir:       cacheDir,
		cacheTTL:       cacheTTL,
		maxBytes:       maxBytes,
		httpClient:     &http.Client{Timeout: fetchTimeout},
	}
}

func normalizeAvatarOrigin(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host)
}

func (p *avatarProxy) sourceURL(value string) (*url.URL, bool) {
	if p == nil || !p.enabled {
		return nil, false
	}
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, false
	}
	return parsed, p.allowedOrigins[strings.ToLower(parsed.Scheme+"://"+parsed.Host)]
}

func avatarVersion(user User) string {
	sum := sha256.Sum256([]byte(strconv.FormatInt(user.ID, 10) + "\x00" + strings.TrimSpace(user.AvatarURL)))
	return hex.EncodeToString(sum[:12])
}

func (p *avatarProxy) publicURL(user User) string {
	rawURL := strings.TrimSpace(user.AvatarURL)
	if rawURL == "" {
		return ""
	}
	if p == nil || !p.configured {
		return rawURL
	}
	if !p.enabled {
		return ""
	}
	if user.ID <= 0 {
		return ""
	}
	if _, ok := p.sourceURL(user.AvatarURL); !ok {
		return ""
	}
	return p.publicOrigin + "/api/auth/avatar/" + avatarVersion(user)
}

func (p *avatarProxy) cacheUserDir(user User) string {
	return filepath.Join(p.cacheDir, strconv.FormatInt(user.ID, 10))
}

func (p *avatarProxy) findCachedAvatar(user User, version string) (string, os.FileInfo) {
	userDir := p.cacheUserDir(user)
	for extension := range avatarContentTypeByExtension {
		candidate := filepath.Join(userDir, version+extension)
		info, err := os.Lstat(candidate)
		if err == nil && info.Mode().IsRegular() {
			return candidate, info
		}
	}
	return "", nil
}

func (p *avatarProxy) lockFor(key string) *sync.Mutex {
	value, _ := p.locks.LoadOrStore(key, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func (p *avatarProxy) download(ctx context.Context, rawURL string) ([]byte, string, error) {
	currentURL := strings.TrimSpace(rawURL)
	client := *p.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	for redirects := 0; redirects <= avatarProxyMaxRedirects; redirects++ {
		if _, ok := p.sourceURL(currentURL); !ok {
			return nil, "", errors.New("avatar source origin is not allowed")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Accept", "image/avif,image/webp,image/png,image/jpeg,image/gif")
		req.Header.Set("User-Agent", "ZenMind-Avatar-Proxy/1.0")
		response, err := client.Do(req)
		if err != nil {
			return nil, "", err
		}
		if response.StatusCode == http.StatusMovedPermanently ||
			response.StatusCode == http.StatusFound ||
			response.StatusCode == http.StatusSeeOther ||
			response.StatusCode == http.StatusTemporaryRedirect ||
			response.StatusCode == http.StatusPermanentRedirect {
			_ = response.Body.Close()
			if redirects == avatarProxyMaxRedirects {
				return nil, "", errors.New("avatar redirect limit exceeded")
			}
			location := strings.TrimSpace(response.Header.Get("Location"))
			if location == "" {
				return nil, "", errors.New("avatar redirect is missing location")
			}
			base, _ := url.Parse(currentURL)
			next, err := base.Parse(location)
			if err != nil {
				return nil, "", errors.New("avatar redirect URL is invalid")
			}
			currentURL = next.String()
			continue
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return nil, "", fmt.Errorf("avatar upstream returned %d", response.StatusCode)
		}
		contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil {
			_ = response.Body.Close()
			return nil, "", errors.New("avatar content type is invalid")
		}
		extension := avatarExtensionByContentType[strings.ToLower(contentType)]
		if extension == "" {
			_ = response.Body.Close()
			return nil, "", errors.New("avatar content type is not supported")
		}
		if response.ContentLength > p.maxBytes {
			_ = response.Body.Close()
			return nil, "", errors.New("avatar response is too large")
		}
		content, err := io.ReadAll(io.LimitReader(response.Body, p.maxBytes+1))
		_ = response.Body.Close()
		if err != nil {
			return nil, "", err
		}
		if len(content) == 0 || int64(len(content)) > p.maxBytes {
			return nil, "", errors.New("avatar response is too large")
		}
		return content, extension, nil
	}
	return nil, "", errors.New("avatar redirect limit exceeded")
}

func (p *avatarProxy) writeCache(user User, version, extension string, content []byte) (string, error) {
	userDir := p.cacheUserDir(user)
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		return "", err
	}
	targetPath := filepath.Join(userDir, version+extension)
	temporary, err := os.CreateTemp(userDir, "."+version+"-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, targetPath); err != nil {
		return "", err
	}
	entries, _ := os.ReadDir(userDir)
	for _, entry := range entries {
		if entry.Name() != filepath.Base(targetPath) && !entry.IsDir() {
			_ = os.Remove(filepath.Join(userDir, entry.Name()))
		}
	}
	return targetPath, nil
}

func (p *avatarProxy) serveFile(w http.ResponseWriter, r *http.Request, filePath, version string, info os.FileInfo) {
	contentType := avatarContentTypeByExtension[strings.ToLower(filepath.Ext(filePath))]
	if contentType == "" {
		http.NotFound(w, r)
		return
	}
	etag := `"` + version + `"`
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", etag)
	if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, filepath.Base(filePath), info.ModTime(), bytes.NewReader(content))
}

func (p *avatarProxy) serve(w http.ResponseWriter, r *http.Request, user User, version string) {
	if p == nil || !p.enabled || version == "" || version != avatarVersion(user) {
		http.NotFound(w, r)
		return
	}
	if _, ok := p.sourceURL(user.AvatarURL); !ok {
		http.NotFound(w, r)
		return
	}
	cachePath, cacheInfo := p.findCachedAvatar(user, version)
	if cacheInfo != nil && time.Since(cacheInfo.ModTime()) < p.cacheTTL {
		p.serveFile(w, r, cachePath, version, cacheInfo)
		return
	}

	lock := p.lockFor(strconv.FormatInt(user.ID, 10) + ":" + version)
	lock.Lock()
	defer lock.Unlock()
	cachePath, cacheInfo = p.findCachedAvatar(user, version)
	if cacheInfo != nil && time.Since(cacheInfo.ModTime()) < p.cacheTTL {
		p.serveFile(w, r, cachePath, version, cacheInfo)
		return
	}
	content, extension, err := p.download(r.Context(), user.AvatarURL)
	if err != nil {
		if cacheInfo != nil {
			p.serveFile(w, r, cachePath, version, cacheInfo)
			return
		}
		writeError(w, http.StatusBadGateway, "avatar_unavailable", "Avatar is temporarily unavailable.")
		return
	}
	cachePath, err = p.writeCache(user, version, extension, content)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "avatar_cache_failed", "Unable to cache avatar.")
		return
	}
	cacheInfo, err = os.Stat(cachePath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "avatar_cache_failed", "Unable to read cached avatar.")
		return
	}
	p.serveFile(w, r, cachePath, version, cacheInfo)
}
