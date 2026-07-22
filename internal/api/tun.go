package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleGetTUN(w http.ResponseWriter, r *http.Request) {
	if s.tun == nil {
		writeErr(w, http.StatusServiceUnavailable, "tun config not available")
		return
	}
	writeJSON(w, http.StatusOK, s.tun.Get())
}

func (s *Server) handleSetTUN(w http.ResponseWriter, r *http.Request) {
	if s.tun == nil {
		writeErr(w, http.StatusServiceUnavailable, "tun config not available")
		return
	}
	var req apitypes.TUNConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	prev := s.tun.Get()
	cfg, err := s.tun.Set(req) // validates
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.tunApplier != nil {
		if err := s.tunApplier.SetTUN(cfg); err != nil {
			_, _ = s.tun.Set(prev) // roll back the store to match the running plane
			writeErr(w, http.StatusBadGateway, "apply tun: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, cfg)
}
