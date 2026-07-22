package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	if s.dns == nil {
		writeErr(w, http.StatusServiceUnavailable, "dns config not available")
		return
	}
	writeJSON(w, http.StatusOK, s.dns.Get())
}

func (s *Server) handleSetDNS(w http.ResponseWriter, r *http.Request) {
	if s.dns == nil {
		writeErr(w, http.StatusServiceUnavailable, "dns config not available")
		return
	}
	var req apitypes.DNSConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	prev := s.dns.Get()
	cfg, err := s.dns.Set(req) // validates
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.dnsApplier != nil {
		if err := s.dnsApplier.SetDNS(cfg); err != nil {
			_, _ = s.dns.Set(prev) // roll back the store to match the running plane
			writeErr(w, http.StatusBadGateway, "apply dns: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, cfg)
}
