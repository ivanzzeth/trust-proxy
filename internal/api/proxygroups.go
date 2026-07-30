package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// wireFailover converts the wire/profile shape into the store shape. Profiles
// and posture slots must carry it: activating a snapshot that dropped the field
// would silently re-enable connection interruption on someone who turned it off.
func wireFailover(f apitypes.ProxyFailover) proxygroups.Failover {
	return proxygroups.Failover{
		ProbeIntervalSeconds:         f.ProbeIntervalSeconds,
		ToleranceMS:                  f.ToleranceMS,
		IdleTimeoutSeconds:           f.IdleTimeoutSeconds,
		InterruptExistingConnections: f.InterruptExistingConnections,
	}
}

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
