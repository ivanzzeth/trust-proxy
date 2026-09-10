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

func (b boxScorer) NoteProbe(tag string, success bool, latency time.Duration) {
	if b.store != nil {
		b.store.NoteProbe(tag, success, latency)
	}
}

func (b boxScorer) TieMargin() float64 { return float64(b.store.Config().TieMargin()) }

// NoteProbe forwards a Clash / urltest probe success into the scorer so
// blackhole / open-breaker members can recover without already carrying traffic.
func (m *Manager) NoteProbe(tag string, success bool, latency time.Duration) {
	if m != nil && m.scores != nil && m.scorableMember(tag) {
		m.scores.NoteProbe(tag, success, latency)
	}
}

// setEligibleMembers records the tags that may be scored. Called from rebuild()
// with the post-FilterEligibleNodes list, i.e. exactly the outbounds the data
// plane can actually dial.
func (m *Manager) setEligibleMembers(nodes []apitypes.Node, eps []apitypes.Endpoint) {
	var epTags []string
	for _, e := range eps {
		if e.Enabled && e.Tag != "" {
			epTags = append(epTags, e.Tag)
		}
	}
	set := make(map[string]struct{})
	for _, t := range memberTags(nodes, epTags) {
		set[proxyscore.NormalizeTag(t)] = struct{}{}
	}
	m.eligible.Store(&set)
}

// scorableMember reports whether tag names an outbound that can actually carry
// traffic, so an observation about it means something.
//
// The case this exists for: a connection is tracked when it starts, and
// detector.outStr follows a group to the member in use via Now(). Right after a
// rebuild a freshly built urltest group has not elected anyone yet, Now() is
// empty, and the group's own tag comes through instead. Measured on a live
// gateway: `🇺🇸 US` and `🇯🇵 JP` — country *groups* — had score records, with
// blackhole_streak 2 and 1. Two more such connections and the blackhole verdict
// would have condemned the group itself: score 0, breaker forced open. That group
// is what a pinned rule targets (Claude → US), so the thing being condemned would
// have been the user's deliberate choice of exit, while every member of it kept
// working.
//
// The sample is dropped rather than reattributed. At track time the group really
// had no selection, so the member is not knowable there; recovering it needs the
// dial chain at finalize, which is a bigger change than refusing to act on an
// attribution we know is wrong.
//
// An empty set means "not built yet" and allows everything: before the first
// rebuild there is no member list to check against, and silently discarding the
// first connections of a gateway's life would be worse than a stale tag.
func (m *Manager) scorableMember(tag string) bool {
	set := m.eligible.Load()
	if set == nil || len(*set) == 0 {
		return true
	}
	_, ok := (*set)[proxyscore.NormalizeTag(tag)]
	return ok
}

// RecordTransfer feeds the throughput term from a finished connection, and the
// blackhole detector — a node that completes handshakes and relays nothing is
// invisible to the dial path, which only ever sees a successful dial.
func (m *Manager) RecordTransfer(tag string, t proxyscore.Transfer) {
	if m.scores != nil && m.scorableMember(tag) {
		m.scores.RecordTransfer(tag, t)
	}
}

// RecordEvent is the finalize-sink entry point: it derives the transfer sample
// from a closed connection and feeds it to the scorer. Callers hand over the
// whole event rather than picking fields, so the mapping exists once — a second
// copy in the caller is how a field stops being read without anything failing.
func (m *Manager) RecordEvent(ev detect.Event) {
	if m.scores == nil || ev.DurationMS <= 0 || !m.scorableMember(ev.Outbound) {
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
//
// Airport info lines are dropped. A subscription ships rows like
// "35.77 GB | 300 GB", "Expire Date: 2027-07-23" and "Traffic Reset: 25 Days
// Left" — quota text shaped like a proxy. They are already kept out of every
// urltest group, so they can never carry a byte, but the score list was built
// from the raw node list and showed all three sitting at "100, preferred",
// indistinguishable from the best real exit in the table (observed on a live
// gateway). A row that cannot be selected has no score to report.
//
// Operator-disabled nodes stay: a disabled node is a real exit somebody turned
// off, and its history is usually the reason they did.
func (m *Manager) MemberTags() []string {
	m.mu.Lock()
	nodes := append(append([]apitypes.Node(nil), m.nodes...), m.gwExits...)
	eps := append([]apitypes.Endpoint(nil), m.endpoints...)
	m.mu.Unlock()
	// nil disabled set: FilterEligibleNodes then removes junk only.
	nodes = FilterEligibleNodes(nodes, nil)
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
