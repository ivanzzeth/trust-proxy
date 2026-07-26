package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// User administration. Every route here is admin-only (see requirement()).
//
// Changing a proxy password has a side effect the caller must not have to think
// about: the mixed inbound's credential list is derived from these accounts, so it
// has to be pushed to the running data plane in the same request. Forgetting that
// is how a UI ends up showing a credential that does not work yet.

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	writeArray(w, http.StatusOK, s.users.List())
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	u, err := s.users.Create(req.Username, req.Password, req.Role)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// handlePatchUser applies any subset of {role, disabled, password, proxy_password}.
func (s *Server) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	id := r.PathValue("id")
	var req struct {
		Role          *string `json:"role,omitempty"`
		Disabled      *bool   `json:"disabled,omitempty"`
		Password      *string `json:"password,omitempty"`
		ProxyPassword *string `json:"proxy_password,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Role != nil {
		if err := s.users.SetRole(id, *req.Role); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Disabled != nil {
		if err := s.users.SetDisabled(id, *req.Disabled); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Password != nil {
		if err := s.users.SetPassword(id, *req.Password); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.ProxyPassword != nil {
		if err := s.users.SetProxyPassword(id, *req.ProxyPassword); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// Disabling an account, or touching a proxy password, changes who may use the
	// proxy — push it to the data plane now, not at the next restart.
	if req.ProxyPassword != nil || req.Disabled != nil {
		if err := s.syncInboundCredentials(); err != nil {
			writeErr(w, http.StatusBadGateway, "apply inbound credentials: "+err.Error())
			return
		}
	}
	u, ok := s.users.ByID(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "no such user")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	if err := s.users.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.syncInboundCredentials(); err != nil {
		writeErr(w, http.StatusBadGateway, "apply inbound credentials: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	var req struct {
		Label     string `json:"label"`
		ExpiresIn int    `json:"expires_in_days,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	var ttl time.Duration
	if req.ExpiresIn > 0 {
		ttl = time.Duration(req.ExpiresIn) * 24 * time.Hour
	}
	created, err := s.users.CreateAPIKey(r.PathValue("id"), req.Label, ttl)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// The only response that ever carries the raw key.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, created)
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	if err := s.users.DeleteAPIKey(r.PathValue("id"), r.PathValue("keyID")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// syncInboundCredentials pushes the derived credential list to the data plane.
func (s *Server) syncInboundCredentials() error {
	if s.inbApplier == nil || s.users == nil {
		return nil
	}
	return s.inbApplier.SetInbound(apitypes.InboundAuth{Users: s.users.ProxyCredentials()})
}
