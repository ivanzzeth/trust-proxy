package api

import (
	"encoding/json"
	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/netwatch"
	"net/http"
	"strconv"

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

// QueryStatsProvider exposes the engine's query-level counters.
type QueryStatsProvider interface {
	QueryStats(top int) detect.QueryStats
}

// handleDNSQueryStats reports what the resolver has been asked for: totals,
// NXDOMAIN share and the busiest parents. Query-level activity is the only place
// a DGA sweep or a DNS tunnel is visible — neither becomes a connection.
func (s *Server) handleDNSQueryStats(w http.ResponseWriter, r *http.Request) {
	if s.queryStats == nil {
		writeErr(w, http.StatusServiceUnavailable, "query stats not available")
		return
	}
	top := 10
	if v := r.URL.Query().Get("top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			top = n
		}
	}
	writeJSON(w, http.StatusOK, s.queryStats.QueryStats(top))
}

// NetworkStateProvider exposes the host routing / interface observation.
type NetworkStateProvider interface {
	Snapshot() netwatch.Snapshot
}

// handleNetcheck reports the host-level picture: which interface carries our
// tunnel, what is genuinely on-link, and how many routes exist. This is the view
// that makes tunnel bypasses visible — they never reach the data plane.
func (s *Server) handleNetcheck(w http.ResponseWriter, r *http.Request) {
	if s.netstate == nil {
		writeJSON(w, http.StatusOK, map[string]any{"supported": false})
		return
	}
	snap := s.netstate.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"supported":   netwatch.RouteWatchSupported(),
		"taken":       snap.Taken,
		"routes":      snap.Routes,
		"host_routes": snap.HostRoutes,
		"local_nets":  snap.LocalNets,
		"tun_ifaces":  snap.TunIfaces,
		"default_via": snap.DefaultVia,
	})
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
