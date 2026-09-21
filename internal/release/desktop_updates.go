package release

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

var ErrDesktopUpdateNotFound = errors.New("desktop update not configured")
var ErrInvalidDesktopUpdate = errors.New("invalid desktop update manifest")

const MaxDesktopManifestBytes = 256 * 1024

type DesktopArtifact struct {
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type DesktopManifest struct {
	SchemaVersion int                        `json:"schemaVersion"`
	ProductID     string                     `json:"productId"`
	Version       string                     `json:"version"`
	PublishedAt   string                     `json:"publishedAt"`
	ReleaseNotes  map[string][]string        `json:"releaseNotes"`
	Artifacts     map[string]DesktopArtifact `json:"artifacts"`
}

var desktopProductPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var desktopVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
var desktopLocalePattern = regexp.MustCompile(`^[a-z]{2}(-[A-Za-z]{2,8})?$`)
var desktopHashPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func ValidateDesktopManifest(m DesktopManifest) error {
	invalid := func(field string) error { return fmt.Errorf("%w: %s", ErrInvalidDesktopUpdate, field) }
	if m.SchemaVersion != 1 || !desktopProductPattern.MatchString(m.ProductID) {
		return invalid("schemaVersion or productId")
	}
	if len(m.Version) > 128 || !desktopVersionPattern.MatchString(m.Version) {
		return invalid("version")
	}
	versionCore := strings.SplitN(m.Version, "+", 2)[0]
	if parts := strings.SplitN(versionCore, "-", 2); len(parts) == 2 {
		for _, id := range strings.Split(parts[1], ".") {
			if len(id) > 1 && id[0] == '0' && strings.Trim(id, "0123456789") == "" {
				return invalid("prerelease version")
			}
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, m.PublishedAt); err != nil {
		return invalid("publishedAt")
	}
	if m.ReleaseNotes == nil {
		return invalid("releaseNotes")
	}
	for locale, notes := range m.ReleaseNotes {
		if !desktopLocalePattern.MatchString(locale) || notes == nil || len(notes) > 100 {
			return invalid("releaseNotes")
		}
		for _, note := range notes {
			if len(utf16.Encode([]rune(note))) > 2000 {
				return invalid("releaseNotes item")
			}
		}
	}
	if len(m.Artifacts) == 0 || len(m.Artifacts) > 4 {
		return invalid("artifacts")
	}
	for platform, artifact := range m.Artifacts {
		extension := ""
		switch platform {
		case "darwin-arm64", "darwin-x64":
			extension = ".zip"
		case "win32-arm64", "win32-x64":
			extension = ".exe"
		default:
			return invalid("artifact platform")
		}
		u, err := url.Parse(artifact.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.Contains(artifact.URL, "#") || !strings.HasSuffix(strings.ToLower(u.EscapedPath()), extension) {
			return invalid("artifact URL")
		}
		if artifact.Size <= 0 || artifact.Size > 16*1024*1024*1024 || !desktopHashPattern.MatchString(artifact.SHA256) {
			return invalid("artifact size or sha256")
		}
	}
	data, err := json.Marshal(m)
	if err != nil || len(data) > MaxDesktopManifestBytes {
		return invalid("manifest size")
	}
	return nil
}
