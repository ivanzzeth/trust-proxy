package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/endpoints"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
	if s.eps == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.eps.List())
}

// handleAddEndpoint accepts either a WireGuard wg-quick paste ({type:wireguard,
// tag, conf}) or explicit fields (wireguard or tailscale).
func (s *Server) handleAddEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.eps == nil {
		writeErr(w, http.StatusServiceUnavailable, "endpoints not available")
		return
	}
	var req struct {
		apitypes.Endpoint
		Conf string `json:"conf"` // wg-quick text (wireguard only)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ep := req.Endpoint
	if ep.Type == "wireguard" && req.Conf != "" {
		parsed, err := endpoints.ParseWgQuick(ep.Tag, req.Conf)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "parse wg config: "+err.Error())
			return
		}
		ep = parsed
	}
	prev := s.eps.All()
	pub, err := s.eps.Add(ep)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.applyEndpoints(prev); err != nil {
		writeErr(w, http.StatusBadGateway, "apply endpoint: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, pub)
}

func (s *Server) handlePatchEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.eps == nil {
		writeErr(w, http.StatusServiceUnavailable, "endpoints not available")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	prev := s.eps.All()
	if _, err := s.eps.SetEnabled(r.PathValue("tag"), req.Enabled); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err := s.applyEndpoints(prev); err != nil {
		writeErr(w, http.StatusBadGateway, "apply endpoint: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.eps.List())
}

func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.eps == nil {
		writeErr(w, http.StatusServiceUnavailable, "endpoints not available")
		return
	}
	prev := s.eps.All()
	if _, err := s.eps.Delete(r.PathValue("tag")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err := s.applyEndpoints(prev); err != nil {
		writeErr(w, http.StatusBadGateway, "apply endpoint: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// applyEndpoints hot-reloads; on failure it rolls the store back to prev so it
// matches the running plane.
func (s *Server) applyEndpoints(prev []apitypes.Endpoint) error {
	if s.epApplier == nil {
		return nil
	}
	if err := s.epApplier.SetEndpoints(s.eps.All()); err != nil {
		_ = s.eps.Restore(prev)
		return err
	}
	return nil
}
