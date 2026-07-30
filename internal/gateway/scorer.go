package gateway

import (
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/proxyscore"
)

// boxScorer adapts our proxyscore.Store to the fork's adapter.OutboundScorer.
// The two signatures differ on purpose: the store speaks in Outcome values
// (which grow fields as the engine learns more), while the interface crossing
// into sing-box stays a flat, allocation-free call — it runs on the dial path.
//
// The store hangs off Manager, not off the box, so every score survives the
// rebuild that each apply performs. Rebuilding is routine here (a subscription
// apply, an ACL edit); if scores lived in the instance, the very act of adding
// one node would reset what we know about all the others.
type boxScorer struct{ store *proxyscore.Store }

func (b boxScorer) Score(tag string) (float64, bool) { return b.store.Score(tag) }

func (b boxScorer) Observe(tag string, success bool, latency time.Duration, err error) {
	o := proxyscore.Outcome{Success: success, Latency: latency}
	if err != nil {
		o.Err = err.Error()
	}
	b.store.Observe(tag, o)
}

func (b boxScorer) TieMargin() float64 { return float64(b.store.Config().TieMargin()) }

// RecordTransfer feeds the throughput term from a finished connection.
func (m *Manager) RecordTransfer(tag string, bytes int64, d time.Duration) {
	if m.scores != nil {
		m.scores.RecordTransfer(tag, bytes, d)
	}
}

// Scores returns the current scoring view for the given tags (unseen tags come
// back as warming-with-100, so the UI lists every member rather than only the
// ones that happen to have carried traffic).
func (m *Manager) Scores(tags []string) []proxyscore.View {
	if m.scores == nil {
		return []proxyscore.View{}
	}
	return m.scores.Snapshot(tags)
}

// ScoringConfig returns the scoring policy currently in force.
func (m *Manager) ScoringConfig() proxyscore.Config {
	if m.scores == nil {
		return proxyscore.Config{}
	}
	return m.scores.Config()
}

// ResetScores discards every observation, putting all members back into warm-up.
// The escape hatch for "I changed provider and the old numbers describe a
// different path" — the same reason observations expire after StaleHours.
func (m *Manager) ResetScores() {
	if m.scores != nil {
		m.scores.Reset()
	}
}

// FlushScores persists observations. Called periodically and at shutdown.
func (m *Manager) FlushScores() error {
	if m.scores == nil {
		return nil
	}
	return m.scores.Flush()
}
