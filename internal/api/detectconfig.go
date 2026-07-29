package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/detectcfg"
	"github.com/ivanzzeth/trust-proxy/internal/netwatch"
	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
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

// FingerprintProvider exposes observed TLS client fingerprints.
type FingerprintProvider interface {
	Fingerprints(limit int) []detect.FingerprintRow
	FingerprintLearning() (bool, string)
}

// handleFingerprints lists the TLS client stacks seen on this machine. The
// baseline window is reported alongside: during it nothing is alerted, and a
// console that didn't say so would look like it had found nothing.
func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	if s.fingerprints == nil {
		writeErr(w, http.StatusServiceUnavailable, "fingerprints not available")
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	learning, until := s.fingerprints.FingerprintLearning()
	writeJSON(w, http.StatusOK, map[string]any{
		"learning":       learning,
		"learning_until": until,
		"fingerprints":   s.fingerprints.Fingerprints(limit),
	})
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

// handlePermitQuarantine is the false-positive recovery path: release the
// gateway's own ban AND add the destination to Permit so default-deny doesn't
// immediately re-block dial-by-IP traffic (frp/SSH to an EIP). Release alone
// only lifts the L1 floor — without Permit the connection still dies under
// Strict, which looks identical to "still banned".
func (s *Server) handlePermitQuarantine(w http.ResponseWriter, r *http.Request) {
	if s.quar == nil {
		writeErr(w, http.StatusServiceUnavailable, "quarantine not available")
		return
	}
	if s.wl == nil {
		writeErr(w, http.StatusServiceUnavailable, "whitelist not available")
		return
	}
	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Value) == "" {
		writeErr(w, http.StatusBadRequest, "value is required")
		return
	}
	value := strings.TrimSpace(req.Value)

	var entry quarantine.Entry
	found := false
	for _, e := range s.quar.Get().Entries {
		if strings.EqualFold(e.Value, value) {
			entry = e
			found = true
			break
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, "not quarantined: "+value)
		return
	}

	prevWL := s.wl.Get()
	prevQ := s.quar.Get()

	var (
		wlRules whitelist.Rules
		err     error
	)
	if entry.IsIP {
		wlRules, err = s.wl.AddIP(entry.Value)
	} else {
		wlRules, err = s.wl.AddDomain(entry.Value)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.wlApplier != nil {
		if err := s.wlApplier.SetWhitelist(wlRules); err != nil {
			_, _ = s.wl.Set(prevWL)
			writeErr(w, http.StatusBadGateway, "apply whitelist: "+err.Error())
			return
		}
	}

	list, err := s.quar.Release(entry.Value)
	if err != nil {
		_, _ = s.wl.Set(prevWL)
		if s.wlApplier != nil {
			_ = s.wlApplier.SetWhitelist(prevWL)
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.quarApplier != nil {
		if err := s.quarApplier.ApplyQuarantine(list); err != nil {
			_, _ = s.quar.Clear()
			for _, e := range prevQ.Entries {
				_, _ = s.quar.Add(nonIP(e), ipOf(e), e.Reason)
			}
			_ = s.quarApplier.ApplyQuarantine(prevQ)
			_, _ = s.wl.Set(prevWL)
			if s.wlApplier != nil {
				_ = s.wlApplier.SetWhitelist(prevWL)
			}
			writeErr(w, http.StatusBadGateway, "apply quarantine: "+err.Error())
			return
		}
	}

	kind := "domain"
	if entry.IsIP {
		kind = "ip"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"quarantine": nonNil(list.Entries),
		"permitted":  map[string]string{"type": kind, "value": entry.Value},
	})
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
