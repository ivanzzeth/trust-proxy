package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/proxyscore"
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

// failoverWire is the other direction. It exists so the mapping is written
// once: policysnapshot.go used to spell it out inline, and a second copy of a
// field list is how the first copy goes stale.
func failoverWire(f proxygroups.Failover) apitypes.ProxyFailover {
	return apitypes.ProxyFailover{
		ProbeIntervalSeconds:         f.ProbeIntervalSeconds,
		ToleranceMS:                  f.ToleranceMS,
		IdleTimeoutSeconds:           f.IdleTimeoutSeconds,
		InterruptExistingConnections: f.InterruptExistingConnections,
	}
}

// wireScoring / scoringWire convert the scoring policy between the wire shape
// and the store shape. Same reason wireFailover exists: the policy travels
// inside profile and posture snapshots, and a snapshot that dropped the field
// would silently restore stock weights over a tuning the user chose.
func wireScoring(c apitypes.ProxyScoring) proxyscore.Config {
	return proxyscore.Config{
		Disabled:            c.Disabled,
		MinSamples:          c.MinSamples,
		WeightReliability:   c.WeightReliability,
		WeightLatency:       c.WeightLatency,
		WeightThroughput:    c.WeightThroughput,
		RewardPerSuccess:    c.RewardPerSuccess,
		PenaltyPerFailure:   c.PenaltyPerFailure,
		MaxStreak:           c.MaxStreak,
		LatencyGoodMS:       c.LatencyGoodMS,
		LatencyBadMS:        c.LatencyBadMS,
		ThroughputGoodKBps:  c.ThroughputGoodKBps,
		TieMarginPoints:     c.TieMarginPoints,
		BreakerFailures:     c.BreakerFailures,
		BreakerDelaySeconds: c.BreakerDelaySeconds,
		BreakerSuccesses:    c.BreakerSuccesses,
		StaleHours:           c.StaleHours,
		BlackholeStreak:      c.BlackholeStreak,
		StreamStallSec:       c.StreamStallSec,
		StreamStallMinUpload: c.StreamStallMinUpload,
		StreamStallMinAgeSec: c.StreamStallMinAgeSec,
	}
}

func scoringWire(c proxyscore.Config) apitypes.ProxyScoring {
	return apitypes.ProxyScoring{
		Disabled:             c.Disabled,
		MinSamples:           c.MinSamples,
		WeightReliability:    c.WeightReliability,
		WeightLatency:        c.WeightLatency,
		WeightThroughput:     c.WeightThroughput,
		RewardPerSuccess:     c.RewardPerSuccess,
		PenaltyPerFailure:    c.PenaltyPerFailure,
		MaxStreak:            c.MaxStreak,
		LatencyGoodMS:        c.LatencyGoodMS,
		LatencyBadMS:         c.LatencyBadMS,
		ThroughputGoodKBps:   c.ThroughputGoodKBps,
		TieMarginPoints:      c.TieMarginPoints,
		BreakerFailures:      c.BreakerFailures,
		BreakerDelaySeconds:  c.BreakerDelaySeconds,
		BreakerSuccesses:     c.BreakerSuccesses,
		StaleHours:           c.StaleHours,
		BlackholeStreak:      c.BlackholeStreak,
		StreamStallSec:       c.StreamStallSec,
		StreamStallMinUpload: c.StreamStallMinUpload,
		StreamStallMinAgeSec: c.StreamStallMinAgeSec,
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
