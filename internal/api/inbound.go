package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleGetInbound(w http.ResponseWriter, r *http.Request) {
	if s.inbound == nil {
		writeErr(w, http.StatusServiceUnavailable, "inbound config not available")
		return
	}
	writeJSON(w, http.StatusOK, s.inbound.Get())
}

func (s *Server) handleSetInbound(w http.ResponseWriter, r *http.Request) {
	if s.inbound == nil {
		writeErr(w, http.StatusServiceUnavailable, "inbound config not available")
		return
	}
	var req apitypes.InboundAuth
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	prev := s.inbound.Get()
	cfg, err := s.inbound.Set(req) // validates
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.inbApplier != nil {
		if err := s.inbApplier.SetInbound(cfg); err != nil {
			_, _ = s.inbound.Set(prev) // roll back the store to match the running plane
			writeErr(w, http.StatusBadGateway, "apply inbound: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, cfg)
}
