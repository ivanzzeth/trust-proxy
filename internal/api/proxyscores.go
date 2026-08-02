package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/proxyscore"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// ProxyScorer exposes the live proxy scoring view (gateway.Manager).
type ProxyScorer interface {
	Scores(tags []string) []proxyscore.View
	ScoringConfig() proxyscore.Config
	ResetScores()
	// NoteProbe heals blackhole / breaker state after a successful delay probe.
	NoteProbe(tag string, success bool, latency time.Duration)
}

func scoreWire(v proxyscore.View) apitypes.ProxyScore {
	return apitypes.ProxyScore{
		Tag: v.Tag, Score: v.Score,
		Reliability: v.Reliability, Latency: v.Latency, Throughput: v.Throughput,
		Samples: v.Samples, MinSamples: v.MinSamples, Warming: v.Warming,
		OKStreak: v.OKStreak, FailStreak: v.FailStreak,
		LatencyMS: v.LatencyMS, ThroughputKBps: v.ThroughputKBps,
		Breaker: v.Breaker, BreakerRemaining: v.BreakerRemaining, Preferred: v.Preferred,
		Blackhole: v.Blackhole, BlackholeStreak: v.BlackholeStreak,
		LastOK: v.LastOK, LastErr: v.LastErr, UpdatedAt: v.UpdatedAt,
	}
}

// handleGetProxyScores answers "why did it pick that node" in one response: the
// per-member breakdown, the policy in force with every default resolved, and
// the formula rendered with the live weights. A client that only got the numbers
// would have to hard-code the arithmetic to explain them, and would then drift.
func (s *Server) handleGetProxyScores(w http.ResponseWriter, r *http.Request) {
	if s.scorer == nil {
		writeErr(w, http.StatusServiceUnavailable, "proxy scores not available")
		return
	}
	cfg := s.scorer.ScoringConfig()
	views := s.scorer.Scores(nil)
	out := apitypes.ProxyScores{
		Scores:  make([]apitypes.ProxyScore, 0, len(views)),
		Config:  scoringWire(cfg.Resolved()),
		Formula: cfg.Formula(),
		Enabled: !cfg.Disabled,
	}
	for _, v := range views {
		out.Scores = append(out.Scores, scoreWire(v))
	}
	// Best first, and demoted (breaker-open) members last regardless of score —
	// the same order the data plane picks in, so the table reads as the ranking
	// rather than as an unordered dump the reader has to sort mentally.
	sort.SliceStable(out.Scores, func(i, j int) bool {
		a, b := out.Scores[i], out.Scores[j]
		if a.Preferred != b.Preferred {
			return a.Preferred
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Tag < b.Tag
	})
	writeJSON(w, http.StatusOK, out)
}

// handleResetProxyScores discards every observation. The escape hatch for "I
// changed provider / moved network and these numbers describe a different
// path" — the same reason observations expire after StaleHours on their own.
func (s *Server) handleResetProxyScores(w http.ResponseWriter, r *http.Request) {
	if s.scorer == nil {
		writeErr(w, http.StatusServiceUnavailable, "proxy scores not available")
		return
	}
	s.scorer.ResetScores()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
