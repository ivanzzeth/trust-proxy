package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleGetRetention(w http.ResponseWriter, r *http.Request) {
	if s.retention == nil {
		writeErr(w, http.StatusServiceUnavailable, "retention config not available")
		return
	}
	writeJSON(w, http.StatusOK, s.retention.Get())
}

func (s *Server) handleSetRetention(w http.ResponseWriter, r *http.Request) {
	if s.retention == nil {
		writeErr(w, http.StatusServiceUnavailable, "retention config not available")
		return
	}
	var req apitypes.Retention
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	prev := s.retention.Get()
	cfg, err := s.retention.Set(req) // validates
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Unlike every other applier here this one does not rebuild the box — both
	// halves just swap a lumberjack. It still rolls the store back on failure,
	// for the same reason: a stored policy the running process is not using is a
	// setting that reads as applied and isn't.
	if s.retApplier != nil {
		if err := s.retApplier.SetRetention(cfg); err != nil {
			_, _ = s.retention.Set(prev)
			writeErr(w, http.StatusBadGateway, "apply retention: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, cfg)
}
