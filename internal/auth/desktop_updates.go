package auth

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/linlay/zenmind-official-server/internal/release"
	"io"
	"net/http"
)

func (s *Server) desktopLatest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !release.ValidUpdateName(r.PathValue("name")) {
		writeError(w, 404, "desktop_update_not_configured", "No update information is configured.")
		return
	}
	if s.desktopUpdates == nil {
		s.updateError(w, errors.New("unavailable"))
		return
	}
	// Directory providers serve the original JSON, including future document fields.
	if files, ok := s.desktopUpdates.(interface {
		GetPublicJSON(context.Context, string) ([]byte, error)
	}); ok {
		data, err := files.GetPublicJSON(r.Context(), r.PathValue("name"))
		if err != nil {
			s.updateError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}
	manifest, err := s.desktopUpdates.GetPublicUpdate(r.Context(), r.PathValue("name"))
	if err != nil {
		s.updateError(w, err)
		return
	}
	if err = release.ValidateDesktopManifest(manifest); err != nil {
		s.updateError(w, err)
		return
	}
	writeJSON(w, 200, manifest)
}
func (s *Server) updateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, release.ErrDesktopUpdateNotFound):
		writeError(w, 404, "desktop_update_not_configured", "No update information is configured.")
	case errors.Is(err, release.ErrUpdateConflict):
		writeError(w, 409, "update_conflict", "This feed has changed. Reload before saving.")
	default:
		writeError(w, 503, "desktop_updates_unavailable", "Update information is unavailable.")
	}
}
func (s *Server) updateAdmin(w http.ResponseWriter, r *http.Request) (User, bool) {
	w.Header().Set("Cache-Control", "no-store")
	user, err := s.currentUser(r)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, 401, "unauthorized", "Login required.")
		} else {
			writeError(w, 403, "forbidden", "Administrator access required.")
		}
		return User{}, false
	}
	if user.Role != "admin" && user.Role != "administrator" {
		writeError(w, 403, "forbidden", "Administrator access required.")
		return User{}, false
	}
	if r.Method == http.MethodPut && !s.requireCSRF(w, r) {
		return User{}, false
	}
	if s.desktopUpdates == nil {
		s.updateError(w, errors.New("unavailable"))
		return User{}, false
	}
	return user, true
}
func (s *Server) adminUpdateList(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.updateAdmin(w, r); !ok {
		return
	}
	items, err := s.desktopUpdates.ListUpdateFeeds(r.Context())
	if err != nil {
		s.updateError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) adminUpdateDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.updateAdmin(w, r); !ok {
		return
	}
	item, err := s.desktopUpdates.GetUpdateFeed(r.Context(), r.PathValue("name"))
	if err != nil {
		s.updateError(w, err)
		return
	}
	writeJSON(w, 200, item)
}
func (s *Server) adminUpdateHistory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.updateAdmin(w, r); !ok {
		return
	}
	items, err := s.desktopUpdates.UpdateFeedHistory(r.Context(), r.PathValue("name"))
	if err != nil {
		s.updateError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) adminUpdateSave(w http.ResponseWriter, r *http.Request) {
	user, ok := s.updateAdmin(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, release.MaxDesktopManifestBytes+8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input release.UpdateFeedInput
	if err := decoder.Decode(&input); err != nil {
		writeError(w, 400, "invalid_update", "Invalid or oversized update configuration.")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, 400, "invalid_update", "Only one JSON object is allowed.")
		return
	}
	item, err := s.desktopUpdates.SaveUpdateFeed(r.Context(), r.PathValue("name"), input, user.ID)
	if errors.Is(err, release.ErrInvalidDesktopUpdate) {
		writeError(w, 400, "invalid_update", err.Error())
		return
	}
	if err != nil {
		s.updateError(w, err)
		return
	}
	writeJSON(w, 200, item)
}
