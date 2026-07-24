package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/finalroute"
)

func (s *Server) handleGetFinal(w http.ResponseWriter, r *http.Request) {
	if s.final == nil {
		writeErr(w, http.StatusServiceUnavailable, "final not available")
		return
	}
	writeJSON(w, http.StatusOK, s.final.Get())
}

func (s *Server) handleSetFinal(w http.ResponseWriter, r *http.Request) {
	if s.final == nil {
		writeErr(w, http.StatusServiceUnavailable, "final not available")
		return
	}
	var req finalroute.Config
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	prev := s.final.Get()
	cfg, err := s.final.Set(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.finalApplier != nil {
		if err := s.finalApplier.SetFinal(cfg.Outbound); err != nil {
			_, _ = s.final.Set(prev)
			writeErr(w, http.StatusBadGateway, "apply final: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, cfg)
}
