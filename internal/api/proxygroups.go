package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
)

func (s *Server) handleGetProxyGroups(w http.ResponseWriter, r *http.Request) {
	if s.pgroups == nil {
		writeErr(w, http.StatusServiceUnavailable, "proxy groups not available")
		return
	}
	writeJSON(w, http.StatusOK, s.pgroups.Get())
}

func (s *Server) handleSetProxyGroups(w http.ResponseWriter, r *http.Request) {
	if s.pgroups == nil {
		writeErr(w, http.StatusServiceUnavailable, "proxy groups not available")
		return
	}
	prev := s.pgroups.Get()
	var req proxygroups.Config
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	cfg, err := s.pgroups.Set(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error()) // validation (bad regex, dup name…)
		return
	}
	if s.pgApplier != nil {
		if err := s.pgApplier.SetProxyGroups(cfg); err != nil {
			_, _ = s.pgroups.Set(prev) // un-poison the store so it matches the running plane
			writeErr(w, http.StatusBadGateway, "apply proxy groups: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, cfg)
}
