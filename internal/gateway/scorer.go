package gateway

import (
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/proxyscore"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
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

// RecordTransfer feeds the throughput term from a finished connection, and the
// blackhole detector — a node that completes handshakes and relays nothing is
// invisible to the dial path, which only ever sees a successful dial.
func (m *Manager) RecordTransfer(tag string, t proxyscore.Transfer) {
	if m.scores != nil {
		m.scores.RecordTransfer(tag, t)
	}
}

// RecordEvent is the finalize-sink entry point: it derives the transfer sample
// from a closed connection and feeds it to the scorer. Callers hand over the
// whole event rather than picking fields, so the mapping exists once — a second
// copy in the caller is how a field stops being read without anything failing.
func (m *Manager) RecordEvent(ev detect.Event) {
	if m.scores == nil || ev.DurationMS <= 0 {
		return
	}
	m.scores.RecordTransfer(ev.Outbound, proxyscore.Transfer{
		Upload:   ev.Upload,
		Download: ev.Download,
		Duration: time.Duration(ev.DurationMS) * time.Millisecond,
		// Connected, not ConnectMs > 0: phase timings are truncated
		// milliseconds, so a fast node reports 0 and would read as "we never
		// reached it". That distinction is the whole basis of the blackhole
		// verdict — a dial that never landed is already a dial failure and is
		// scored on the dial path.
		Handshook: ev.Connected,
	})
}

// Scores returns the current scoring view. A nil tags argument means "every
// live member", derived from the same memberTags used to name the outbounds —
// unseen tags come back warming-at-100, so the list is the node list and not
// merely the subset that happened to carry traffic since the last restart.
func (m *Manager) Scores(tags []string) []proxyscore.View {
	if m.scores == nil {
		return []proxyscore.View{}
	}
	if tags == nil {
		tags = m.MemberTags()
	}
	return m.scores.Snapshot(tags)
}

// MemberTags lists the outbound tags currently in the proxy group: nodes,
// gateway exits and enabled endpoints, named exactly as the data plane names
// them.
func (m *Manager) MemberTags() []string {
	m.mu.Lock()
	nodes := append(append([]apitypes.Node(nil), m.nodes...), m.gwExits...)
	eps := append([]apitypes.Endpoint(nil), m.endpoints...)
	m.mu.Unlock()
	var epTags []string
	for _, e := range eps {
		if e.Enabled && e.Tag != "" {
			epTags = append(epTags, e.Tag)
		}
	}
	return memberTags(nodes, epTags)
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
