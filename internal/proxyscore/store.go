// Package proxyscore scores outbound nodes from *real* traffic, so urltest
// groups can prefer a node that actually works over one that merely answers the
// generate_204 probe quickly.
//
// Three ideas hold the design together, and each exists because of a specific
// failure this gateway has already had:
//
//  1. **Warm-up.** A node scores a neutral 100 until it has MinSamples real
//     outcomes. Judging a node on its first dial during a network change would
//     demote everything at once.
//
//  2. **Streaks, not averages.** The Nth consecutive failure costs N× the
//     first. An average forgets that a node has been dead for the last ten
//     minutes; a streak does not, and it stays explainable — the UI prints the
//     streak next to the score.
//
//  3. **The breaker is orthogonal to the score, and it never excludes.** It
//     answers "can this be used right now" (working from sample #1, which is
//     what stops a dead node riding its warm-up 100 into selection), while the
//     score answers "how good is it". An open breaker demotes a node to last
//     resort — it must NEVER remove it from the candidate set. See
//     third_party/sing-box/protocol/group/urltest_cooldown_test.go: hard
//     exclusion once left this gateway with no egress at all for five minutes.
//
// The package deliberately does not import sing-box; the gateway owns the
// adapter that bridges it to adapter.OutboundScorer.
package proxyscore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/failsafe-go/failsafe-go/circuitbreaker"
)

// Outcome is one real dial attempt through a node.
type Outcome struct {
	Success bool
	// Latency is how long the dial took. Only recorded on success — a failure's
	// duration measures a timeout, not the node's speed.
	Latency time.Duration
	// Err is a short reason, surfaced in the UI as "last result".
	Err string
}

// Stats is the per-tag persisted observation set. Breaker state is NOT part of
// it: a restart should give every node a clean chance rather than resurrect a
// stale "open" that would keep a since-recovered node at last resort.
type Stats struct {
	Tag string `json:"tag"`

	Reliability float64 `json:"reliability"`
	Samples     int     `json:"samples"`
	OKStreak    int     `json:"ok_streak"`
	FailStreak  int     `json:"fail_streak"`

	// LatencyMS and ThroughputKBps are bounded windows; the score uses their
	// median so one outlier cannot move it and a recovered node is not held
	// down by an hour-old disaster.
	LatencyMS      []int     `json:"latency_ms,omitempty"`
	ThroughputKBps []float64 `json:"throughput_kbps,omitempty"`

	LastOK    bool      `json:"last_ok"`
	LastErr   string    `json:"last_err,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`

	breaker circuitbreaker.CircuitBreaker[any]
}

// View is the rendered, explainable form of a Stats: the final score plus every
// input that produced it. The API returns this verbatim so "why is this node at
// 62" is answerable from one response.
type View struct {
	Tag   string  `json:"tag"`
	Score float64 `json:"score"`

	Reliability float64 `json:"reliability"`
	Latency     float64 `json:"latency_score"`
	Throughput  float64 `json:"throughput_score"`

	Samples    int  `json:"samples"`
	MinSamples int  `json:"min_samples"`
	Warming    bool `json:"warming"`

	OKStreak   int `json:"ok_streak"`
	FailStreak int `json:"fail_streak"`

	LatencyMS      int     `json:"latency_ms,omitempty"`
	ThroughputKBps float64 `json:"throughput_kbps,omitempty"`

	// Breaker is "closed" | "half-open" | "open". Preferred is false only while
	// an open breaker is still inside its delay; such a node is sorted last, not
	// dropped.
	Breaker          string `json:"breaker"`
	BreakerRemaining int    `json:"breaker_remaining_seconds,omitempty"`
	Preferred        bool   `json:"preferred"`

	LastOK    bool   `json:"last_ok"`
	LastErr   string `json:"last_err,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Store holds every node's stats, persists them, and answers the data plane's
// Score/Observe calls. Safe for concurrent use; Score is on the dial path and
// must stay allocation-light and lock-brief.
type Store struct {
	path string

	mu    sync.Mutex
	cfg   Config
	stats map[string]*Stats
	dirty bool
}

// New opens (or seeds) the store at path. Observations older than the config's
// StaleHours are dropped on load: after a subscription change or a move to
// another network, yesterday's numbers describe a different path entirely.
// A corrupt or unreadable file is never fatal — scoring starts from a clean
// slate rather than refusing to boot the gateway.
func New(path string, cfg Config) *Store {
	s := &Store{path: path, cfg: cfg, stats: map[string]*Stats{}}
	s.load()
	return s
}

func (s *Store) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var doc struct {
		Stats []*Stats `json:"stats"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return
	}
	cutoff := time.Now().Add(-time.Duration(s.cfg.Stale()) * time.Hour)
	for _, st := range doc.Stats {
		if st == nil || st.Tag == "" || st.UpdatedAt.Before(cutoff) {
			continue
		}
		if st.Reliability < 0 || st.Reliability > 100 {
			st.Reliability = 100
		}
		if st.Samples < 0 {
			st.Samples = 0
		}
		if len(st.LatencyMS) > maxSeries {
			st.LatencyMS = st.LatencyMS[len(st.LatencyMS)-maxSeries:]
		}
		if len(st.ThroughputKBps) > maxSeries {
			st.ThroughputKBps = st.ThroughputKBps[len(st.ThroughputKBps)-maxSeries:]
		}
		s.stats[st.Tag] = st
	}
}

// Config returns the scoring policy currently in force.
func (s *Store) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// SetConfig swaps the policy in live. Observations are kept: a settings change
// should re-weight what we know, not blind the scorer.
//
// Breakers are rebuilt only when their own parameters changed, so tweaking a
// weight cannot reset an open breaker and hand a dead node back to the dialer.
func (s *Store) SetConfig(cfg Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.cfg
	s.cfg = cfg
	if old.BreakFails() != cfg.BreakFails() || old.BreakDelay() != cfg.BreakDelay() || old.BreakOKs() != cfg.BreakOKs() {
		for _, st := range s.stats {
			st.breaker = nil
		}
	}
}

// statLocked returns (creating if needed) the stats for a tag.
func (s *Store) statLocked(tag string) *Stats {
	st := s.stats[tag]
	if st == nil {
		st = &Stats{Tag: tag, Reliability: 100, LastOK: true}
		s.stats[tag] = st
	}
	if st.breaker == nil {
		st.breaker = circuitbreaker.NewBuilder[any]().
			WithFailureThreshold(uint(s.cfg.BreakFails())).
			WithDelay(time.Duration(s.cfg.BreakDelay()) * time.Second).
			WithSuccessThreshold(uint(s.cfg.BreakOKs())).
			Build()
	}
	return st
}

// Observe records one real dial outcome. Called from the data plane's dial
// path, so it must return immediately and never re-enter the router.
func (s *Store) Observe(tag string, o Outcome) {
	if tag == "" || tag == "direct" || tag == "block" || tag == "blocked" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Disabled {
		return
	}
	st := s.statLocked(tag)
	st.Samples++
	st.LastOK = o.Success
	st.LastErr = o.Err
	st.UpdatedAt = time.Now()
	s.dirty = true

	if o.Success {
		st.FailStreak = 0
		st.OKStreak++
		st.Reliability = clamp100(st.Reliability + float64(s.cfg.Reward()*minInt(st.OKStreak, s.cfg.Streak())))
		if o.Latency > 0 {
			st.LatencyMS = pushInt(st.LatencyMS, int(o.Latency.Milliseconds()))
		}
	} else {
		st.OKStreak = 0
		st.FailStreak++
		st.Reliability = clamp100(st.Reliability - float64(s.cfg.Penalty()*minInt(st.FailStreak, s.cfg.Streak())))
	}

	// The breaker only advances state when a permit is acquired first — an
	// isolated RecordSuccess/RecordFailure while open is a no-op, and nothing
	// else would ever move it out of open. (Verified against failsafe-go
	// v0.9.6; do not "simplify" this by dropping the acquire.)
	st.breaker.TryAcquirePermit()
	if o.Success {
		st.breaker.RecordSuccess()
	} else {
		st.breaker.RecordFailure()
	}
}

// RecordTransfer feeds the throughput term from a completed connection. Fed by
// the detect engine's finalize sink, which already resolves the group down to
// the real member — no new data-plane plumbing.
//
// Transfers below minThroughputBytes are ignored: a 200-byte request that took
// 300ms is a small request, not a slow node.
func (s *Store) RecordTransfer(tag string, bytes int64, d time.Duration) {
	if tag == "" || tag == "direct" || tag == "block" || tag == "blocked" {
		return
	}
	if bytes < minThroughputBytes || d <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Disabled {
		return
	}
	st := s.statLocked(tag)
	kbps := float64(bytes) / 1024 / d.Seconds()
	st.ThroughputKBps = pushFloat(st.ThroughputKBps, kbps)
	st.UpdatedAt = time.Now()
	s.dirty = true
}

// Score answers the data plane: the node's score, and whether it may be
// preferred right now.
//
// preferred is false only while an open breaker is inside its delay. Once the
// delay elapses the node becomes preferable again *without* the read path
// touching the breaker: acquiring a trial permit here would burn the half-open
// budget on members that are merely being ranked, not dialed. The transition
// happens in Observe, on the next real dial.
func (s *Store) Score(tag string) (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Disabled {
		return 0, true // all equal => pure latency ordering, i.e. stock sing-box
	}
	st := s.stats[tag]
	if st == nil {
		return 100, true
	}
	return s.scoreLocked(st), preferredOf(st)
}

func preferredOf(st *Stats) bool {
	if st.breaker == nil {
		return true
	}
	return !(st.breaker.IsOpen() && st.breaker.RemainingDelay() > 0)
}

func breakerState(st *Stats) (string, int) {
	if st.breaker == nil {
		return "closed", 0
	}
	rem := int(st.breaker.RemainingDelay() / time.Second)
	switch {
	case st.breaker.IsOpen():
		return "open", rem
	case st.breaker.IsHalfOpen():
		return "half-open", 0
	default:
		return "closed", 0
	}
}

// scoreLocked computes the composite score. During warm-up every node reports
// the neutral 100 — all-equal scores collapse the ordering back to pure
// latency, which is exactly today's behaviour.
func (s *Store) scoreLocked(st *Stats) float64 {
	if st.Samples < s.cfg.Samples() {
		return 100
	}
	rel := clamp100(st.Reliability)
	lat := s.latencyScore(st)
	tp := s.throughputScore(st)
	sum := float64(s.cfg.WRel() + s.cfg.WLat() + s.cfg.WTp())
	if sum <= 0 {
		return rel
	}
	return clamp100((float64(s.cfg.WRel())*rel + float64(s.cfg.WLat())*lat + float64(s.cfg.WTp())*tp) / sum)
}

// latencyScore maps median dial latency onto 0..100. No samples => neutral 50,
// so a node is never rewarded or punished for a number we do not have.
func (s *Store) latencyScore(st *Stats) float64 {
	if len(st.LatencyMS) == 0 {
		return 50
	}
	ms := float64(medianInt(st.LatencyMS))
	good, bad := float64(s.cfg.LatGood()), float64(s.cfg.LatBad())
	switch {
	case ms <= good:
		return 100
	case ms >= bad:
		return 0
	default:
		return 100 * (bad - ms) / (bad - good)
	}
}

// throughputScore maps median KB/s onto 0..100, neutral 50 without samples.
func (s *Store) throughputScore(st *Stats) float64 {
	if len(st.ThroughputKBps) == 0 {
		return 50
	}
	kbps := medianFloat(st.ThroughputKBps)
	good := float64(s.cfg.TpGood())
	if kbps >= good {
		return 100
	}
	return clamp100(100 * kbps / good)
}

// Snapshot renders every known node for the API/CLI/UI. tags, when non-empty,
// also includes members that have no observations yet, so the console lists the
// whole group rather than only the nodes that happen to have been dialed.
func (s *Store) Snapshot(tags []string) []View {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	out := make([]View, 0, len(s.stats)+len(tags))
	for _, st := range s.stats {
		seen[st.Tag] = true
		out = append(out, s.viewLocked(st))
	}
	for _, t := range tags {
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, View{
			Tag: t, Score: 100, Reliability: 100, Latency: 50, Throughput: 50,
			MinSamples: s.cfg.Samples(), Warming: true, Breaker: "closed",
			Preferred: true, LastOK: true,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Tag < out[j].Tag
	})
	return out
}

func (s *Store) viewLocked(st *Stats) View {
	state, rem := breakerState(st)
	v := View{
		Tag:         st.Tag,
		Score:       round1(s.scoreLocked(st)),
		Reliability: round1(clamp100(st.Reliability)),
		Latency:     round1(s.latencyScore(st)),
		Throughput:  round1(s.throughputScore(st)),
		Samples:     st.Samples,
		MinSamples:  s.cfg.Samples(),
		Warming:     st.Samples < s.cfg.Samples(),
		OKStreak:    st.OKStreak,
		FailStreak:  st.FailStreak,

		Breaker:          state,
		BreakerRemaining: rem,
		Preferred:        preferredOf(st),

		LastOK:  st.LastOK,
		LastErr: st.LastErr,
	}
	if len(st.LatencyMS) > 0 {
		v.LatencyMS = medianInt(st.LatencyMS)
	}
	if len(st.ThroughputKBps) > 0 {
		v.ThroughputKBps = round1(medianFloat(st.ThroughputKBps))
	}
	if !st.UpdatedAt.IsZero() {
		v.UpdatedAt = st.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return v
}

// Reset drops all observations (CLI/UI "re-learn"): after swapping a whole
// subscription the old numbers describe nodes that no longer exist.
func (s *Store) Reset() {
	s.mu.Lock()
	s.stats = map[string]*Stats{}
	s.dirty = true
	s.mu.Unlock()
	_ = s.Flush()
}

// Flush persists the observations if anything changed. Stale entries are
// dropped on the way out so the file cannot grow without bound across
// subscription churn. Callers run it on a timer and once at shutdown.
func (s *Store) Flush() error {
	s.mu.Lock()
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return nil
	}
	cutoff := time.Now().Add(-time.Duration(s.cfg.Stale()) * time.Hour)
	list := make([]*Stats, 0, len(s.stats))
	for tag, st := range s.stats {
		if st.UpdatedAt.Before(cutoff) {
			delete(s.stats, tag)
			continue
		}
		cp := *st
		cp.breaker = nil
		list = append(list, &cp)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Tag < list[j].Tag })
	s.dirty = false
	path := s.path
	s.mu.Unlock()

	b, err := json.MarshalIndent(struct {
		Stats []*Stats `json:"stats"`
	}{list}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func clamp100(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

func pushInt(s []int, v int) []int {
	s = append(s, v)
	if len(s) > maxSeries {
		s = s[len(s)-maxSeries:]
	}
	return s
}

func pushFloat(s []float64, v float64) []float64 {
	s = append(s, v)
	if len(s) > maxSeries {
		s = s[len(s)-maxSeries:]
	}
	return s
}

func medianInt(s []int) int {
	c := append([]int(nil), s...)
	sort.Ints(c)
	return c[len(c)/2]
}

func medianFloat(s []float64) float64 {
	c := append([]float64(nil), s...)
	sort.Float64s(c)
	return c[len(c)/2]
}
