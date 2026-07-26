package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/detectcfg"
	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// DetectionApplier pushes tuned thresholds into the running engine.
type DetectionApplier interface {
	ApplyDetectionConfig(apitypes.DetectionConfig)
}

// QuarantineApplier rebuilds the data plane after the quarantine list changes.
type QuarantineApplier interface {
	ApplyQuarantine(quarantine.List) error
}

func (s *Server) handleGetDetectionConfig(w http.ResponseWriter, r *http.Request) {
	if s.detcfg == nil {
		writeErr(w, http.StatusServiceUnavailable, "detection config not available")
		return
	}
	writeJSON(w, http.StatusOK, s.detcfg.Get())
}

func (s *Server) handleSetDetectionConfig(w http.ResponseWriter, r *http.Request) {
	if s.detcfg == nil {
		writeErr(w, http.StatusServiceUnavailable, "detection config not available")
		return
	}
	var req apitypes.DetectionConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	// Validation lives in the store; a rejected document leaves the engine on its
	// previous settings rather than half-applied.
	cfg, err := s.detcfg.Set(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.detApplier != nil {
		s.detApplier.ApplyDetectionConfig(cfg)
	}
	writeJSON(w, http.StatusOK, cfg)
}

// handleListQuarantine reports what the gateway blocked by itself. Kept separate
// from the deny list so a posture switch can't drop it (see internal/quarantine).
func (s *Server) handleListQuarantine(w http.ResponseWriter, r *http.Request) {
	if s.quar == nil {
		writeErr(w, http.StatusServiceUnavailable, "quarantine not available")
		return
	}
	writeArray(w, http.StatusOK, s.quar.Get().Entries)
}

func (s *Server) handleReleaseQuarantine(w http.ResponseWriter, r *http.Request) {
	if s.quar == nil {
		writeErr(w, http.StatusServiceUnavailable, "quarantine not available")
		return
	}
	var req struct {
		Value string `json:"value"`
		All   bool   `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Value == "" && !req.All) {
		writeErr(w, http.StatusBadRequest, "value (or all) is required")
		return
	}
	prev := s.quar.Get()
	var (
		list quarantine.List
		err  error
	)
	if req.All {
		list, err = s.quar.Clear()
	} else {
		list, err = s.quar.Release(req.Value)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.quarApplier != nil {
		if err := s.quarApplier.ApplyQuarantine(list); err != nil {
			// Releasing failed to reach the data plane: put it back so the store
			// keeps matching what is actually enforced.
			_, _ = s.quar.Clear()
			for _, e := range prev.Entries {
				_, _ = s.quar.Add(nonIP(e), ipOf(e), e.Reason)
			}
			writeErr(w, http.StatusBadGateway, "apply quarantine: "+err.Error())
			return
		}
	}
	writeArray(w, http.StatusOK, list.Entries)
}

func nonIP(e quarantine.Entry) string {
	if e.IsIP {
		return ""
	}
	return e.Value
}

func ipOf(e quarantine.Entry) string {
	if e.IsIP {
		return e.Value
	}
	return ""
}

var _ = detectcfg.Defaults
