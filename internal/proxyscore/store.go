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
	"strings"
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

	// LatencyMS and ThroughputKBps are bounded windows. Latency is read as a
	// median so one outlier cannot move it and a recovered node is not held down
	// by an hour-old disaster; throughput is read as a maximum, because an idle
	// connection can only bias a throughput sample downward — see
	// throughputScore.
	LatencyMS      []int     `json:"latency_ms,omitempty"`
	ThroughputKBps []float64 `json:"throughput_kbps,omitempty"`

	// BlackholeStreak counts consecutive connections that completed a handshake
	// through this node, sent bytes, and got nothing back. See RecordTransfer.
	BlackholeStreak int       `json:"blackhole_streak,omitempty"`
	BlackholedAt    time.Time `json:"blackholed_at,omitempty"`

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

	// Blackhole marks a node that completed handshakes but relayed nothing back.
	// Surfaced separately from the score because "0" alone reads as "very slow",
	// and the fix is different: a slow node is worth keeping, this one is not
	// carrying traffic at all.
	Blackhole       bool `json:"blackhole,omitempty"`
	BlackholeStreak int  `json:"blackhole_streak,omitempty"`

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
		if st == nil || st.UpdatedAt.Before(cutoff) {
			continue
		}
		// A file written before tags were normalized holds both spellings of the
		// same node. Fold them here rather than letting the duplicate linger for
		// a whole StaleHours window: whichever half was observed more recently
		// wins, since the two halves never carried the same fields anyway.
		st.Tag = normalizeTag(st.Tag)
		if !scorable(st.Tag) {
			continue
		}
		if prev := s.stats[st.Tag]; prev != nil && prev.UpdatedAt.After(st.UpdatedAt) {
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

// normalizeTag reduces a tag to the one key this package stores it under: the
// bare outbound tag the data plane dials by.
//
// Two callers arrive with two spellings of the same node, and getting this wrong
// is silent. The dial path (the fork's urltest) reports RealTag(outbound) — a
// bare "🇭🇰 Hong Kong丨02". The finalize sink arrives via detect.Event.Outbound,
// which detector.outStr renders as type+"/"+tag for the connections UI —
// "anytls/🇭🇰 Hong Kong丨02". Left unnormalized, every node splits into two
// records: the dial one never receives a throughput sample (so its throughput
// term sits at the neutral 50 forever) and the transfer one never leaves warm-up
// at zero samples. Both halves look plausible on their own, which is why this
// survived unit tests and only showed up as duplicate rows on a real gateway.
//
// Splitting on the FIRST "/" is what makes this safe: a tag may itself contain
// slashes, and the prefix is an outbound type, never a user-chosen name.
// NormalizeTag is normalizeTag for callers that must key on the same identity
// the store does — the gateway checks a tag against the live member list before
// recording, and "anytls/tokyo-01" and "tokyo-01" have to be the same node there
// too, or the check rejects every sample that came through the finalize sink.
func NormalizeTag(tag string) string { return normalizeTag(tag) }

func normalizeTag(tag string) string {
	if i := strings.IndexByte(tag, '/'); i >= 0 {
		if _, isType := outboundTypes[tag[:i]]; isType {
			return tag[i+1:]
		}
	}
	return tag
}

// neutralReliability is "no opinion": the ceiling a successful probe can lift a
// demoted member back to. Real traffic (Observe) is what earns more, and the
// initial value for an unobserved member is 100 — warm-up, not an opinion.
const neutralReliability = 50

// outboundTypes are the sing-box outbound types detector.outStr can prefix a tag
// with. An allow-list rather than "strip anything before a slash": a node named
// "airport/tokyo-01" must keep its name, or it becomes a third distinct key.
var outboundTypes = map[string]struct{}{
	"anytls": {}, "block": {}, "direct": {}, "http": {}, "hysteria": {},
	"hysteria2": {}, "shadowsocks": {}, "shadowtls": {}, "socks": {},
	"ssh": {}, "tor": {}, "trojan": {}, "tuic": {}, "vless": {}, "vmess": {},
	"wireguard": {}, "tailscale": {}, "selector": {}, "urltest": {},
}

// scorable rejects the pseudo-outbounds that are not nodes to choose between.
// Applied AFTER normalizeTag, so "direct/direct" is rejected as "direct".
func scorable(tag string) bool {
	switch tag {
	case "", "direct", "block", "blocked":
		return false
	}
	return true
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
	tag = normalizeTag(tag)
	if !scorable(tag) {
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

// Transfer is one finished connection, as seen by the detect engine's finalize
// sink. It carries more than the byte count because the byte count alone cannot
// tell a working node from a blackhole — see RecordTransfer.
type Transfer struct {
	Upload   int64
	Download int64
	Duration time.Duration
	// Handshook reports that the connection got through this node's own
	// handshake (the gateway derives it from connect_ms/tls_ms being non-zero).
	// It is what separates "the node relayed us to a dead destination" from
	// "we never reached the node at all", which is already a dial failure.
	Handshook bool
}

// RecordTransfer feeds the throughput term, and detects blackhole nodes.
//
// **Throughput.** Transfers below minThroughputBytes are ignored: a 200-byte
// request that took 300ms is a small request, not a slow node.
//
// **Blackholes.** Subscriptions ship nodes that answer their own handshake and
// relay nothing: TCP to the provider's host connects, the proxy handshake
// completes, so the dial is a *success* and reliability climbs — and then the
// real destination never sends a byte back. Scoring was structurally blind to
// this: the dial path only sees a successful dial, and this function used to
// return early on `bytes < minThroughputBytes`, so a connection that moved
// nothing produced no sample at all. A blackhole rode its perfect score to the
// front of the group and swallowed the traffic.
//
// The shape is: the handshake completed, we sent bytes, and nothing came back.
// Requiring Upload > 0 is what keeps a cancelled request out of it — those
// abort before sending. One such connection means little (a fire-and-forget
// push legitimately looks like this), so it takes BlackholeStreak consecutive
// ones on the same node, and any single byte received resets the streak.
//
// On confirmation the node is scored 0 and its breaker forced open, which sorts
// it last for new connections. It is NOT removed from the group: hard exclusion
// once left this gateway with no egress at all. Connections already flowing
// through it are left alone — a wrong call must not sever what the user is
// doing; only the next connection is steered.
func (s *Store) RecordTransfer(tag string, t Transfer) {
	tag = normalizeTag(tag)
	if !scorable(tag) || t.Duration <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Disabled {
		return
	}
	// Decide before touching the map: statLocked creates the record, and a
	// connection we learn nothing from must not conjure a node into the snapshot
	// that the dial path has never seen.
	bytes := t.Upload + t.Download
	countable := bytes >= minThroughputBytes
	limit := s.cfg.Blackhole()
	relevant := limit > 0 && t.Handshook && (t.Download > 0 || t.Upload > 0)
	if !countable && !relevant {
		return
	}

	st := s.statLocked(tag)
	now := time.Now()

	if countable {
		st.ThroughputKBps = pushFloat(st.ThroughputKBps, float64(bytes)/1024/t.Duration.Seconds())
		st.UpdatedAt = now
		s.dirty = true
	}

	if relevant {
		switch {
		case t.Download > 0:
			// Anything came back: this node relays. Clear the streak whether or
			// not it was already confirmed — recovery must not need a restart.
			st.BlackholeStreak = 0
			st.BlackholedAt = time.Time{}
		case t.Upload > 0:
			st.BlackholeStreak++
			st.UpdatedAt = now
			s.dirty = true
			if st.BlackholeStreak >= limit {
				st.BlackholedAt = now
				st.LastOK = false
				st.LastErr = "blackhole: handshake ok, nothing came back"
				// Score 0 is not enough on its own: during warm-up scoreLocked
				// returns the neutral 100 regardless. Zeroing reliability is what
				// makes the 0 hold once samples arrive, and forcing the breaker
				// open is what demotes it *now* — the breaker works from sample
				// #1, which is the whole reason it is separate from the score.
				st.Reliability = 0
				st.OKStreak = 0
				forceBreakerOpen(st)
			}
		}
	}
}

// NoteProbe records a successful urltest / Clash delay probe. The probe fetched
// a generate_204 (or equivalent) *through* the member, so it is conclusive
// counter-evidence for a blackhole verdict — and the recovery path that does
// not require the demoted member to already be carrying user traffic.
//
// Failures are ignored: latency probes are not user traffic and must not reopen
// breakers on their own. Dial Observe(success) must also NOT clear blackholes
// (blackholes complete their handshake, so dials "succeed").
func (s *Store) NoteProbe(tag string, success bool, latency time.Duration) {
	if !success {
		return
	}
	tag = normalizeTag(tag)
	if !scorable(tag) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Disabled {
		return
	}
	st := s.statLocked(tag)
	wasBlackhole := s.blackholedLocked(st)
	st.BlackholeStreak = 0
	st.BlackholedAt = time.Time{}
	if latency > 0 {
		st.LatencyMS = pushInt(st.LatencyMS, int(latency.Milliseconds()))
	}
	// A successful probe rehabilitates a demoted member, but only as far as
	// neutral.
	//
	// It used to heal only a confirmed blackhole, and that left a ratchet with no
	// way out: a member demoted by consecutive dial failures is scored near the
	// bottom, so Select never hands it traffic, so Observe(true) — the only thing
	// that cleared FailStreak — never runs. The probe proved every 30s that the
	// member was fine and the score ignored the proof. Measured on a live gateway
	// after one network-wide blip (laptop sleep, Wi-Fi drop: every member fails at
	// once): 32 of 39 members sat at score 23-29 with fail_streak 29-31 and a
	// fresh 94-318ms probe delay, i.e. `last_ok: true` and `reliability: 0` in the
	// same record. Throughput through the one surviving member was 4x worse than
	// the subscription could do. One blip, and the whole subscription was
	// condemned until someone reset the store by hand.
	//
	// Neutral and no further, because a probe is weak evidence: generate_204 can
	// pass while real TLS to the actual destination still fails, which is exactly
	// what urltest's own dial cooldown exists for. Healing to 50 puts the member
	// back in contention behind everything with real traffic behind it, and the
	// next real failure demotes it again immediately.
	//
	// This does not let a probe *punish* (that rule is in urlTest: a failed probe
	// deliberately does not Observe(false)) and it does not clear a blackhole on
	// its own — BlackholeStreak above is reset because bytes did come back through
	// the member, which is the blackhole's own disproof.
	// Two separate things, which the first version of this wrongly did under one
	// condition — so a member sitting at reliability 92 with a stale streak of 1
	// never shed it (seen on the live gateway right after deploying that version).
	//
	// The streak decays by one per successful probe rather than resetting. It
	// means "consecutive failures with nothing good in between", and a probe is
	// partial evidence that the run ended — partial because generate_204 can pass
	// while real TLS to the destination still fails. Resetting it would let such
	// a member dodge the escalating penalty forever (failure, probe, failure,
	// probe…, each failure charged once instead of N times), and the escalation is
	// what makes a genuinely broken member drop fast. Decaying lets a member that
	// really did recover walk back to zero over a few rounds, while one that keeps
	// failing real traffic outruns the decay.
	if st.FailStreak > 0 {
		st.FailStreak--
	}
	// The reliability lift is a floor, never a ceiling: it rescues a member the
	// ratchet had pinned at the bottom and leaves a healthy one alone.
	if st.Reliability < neutralReliability {
		st.Reliability = neutralReliability
	}
	st.LastOK = true
	if wasBlackhole {
		st.LastErr = ""
	}
	st.UpdatedAt = time.Now()
	s.dirty = true
	// Only record a success when a permit was acquired. During the open delay
	// TryAcquirePermit is false and an orphan RecordSuccess is a no-op for
	// state — but after the delay it is what moves Open → HalfOpen → Closed.
	// Without probes calling this, a demoted node never gets a trial.
	if st.breaker.TryAcquirePermit() {
		st.breaker.RecordSuccess()
	}
}

// RecordStreamStall demotes a member after the gateway killed a live connection
// that uploaded a large payload and then went silent on download. Unlike
// blackhole confirmation (finalize-only, download==0), this fires mid-stream so
// the client's retry is not stuck on the same dead member.
func (s *Store) RecordStreamStall(tag string) {
	tag = normalizeTag(tag)
	if !scorable(tag) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Disabled || s.cfg.StreamStall() <= 0 {
		return
	}
	st := s.statLocked(tag)
	st.OKStreak = 0
	st.FailStreak++
	st.Reliability = clamp100(st.Reliability - float64(s.cfg.Penalty()*minInt(st.FailStreak, s.cfg.Streak())))
	st.LastOK = false
	st.LastErr = "stream stall: upload then silence (conn killed)"
	st.UpdatedAt = time.Now()
	st.Samples++
	s.dirty = true
	forceBreakerOpen(st)
}

// forceBreakerOpen trips the breaker regardless of its failure threshold. Used
// for blackhole confirmation, where the evidence is already conclusive and
// waiting for BreakerFailures more dead connections would mean waiting for more
// traffic to be swallowed. failsafe-go only advances state while a permit is
// held, so each failure is recorded behind its own acquire.
func forceBreakerOpen(st *Stats) {
	if st.breaker == nil {
		return
	}
	for i := 0; i < maxBreakerTrip && !st.breaker.IsOpen(); i++ {
		st.breaker.TryAcquirePermit()
		st.breaker.RecordFailure()
	}
}

// Score answers the data plane: the node's score, and whether it may be
// preferred right now.
//
// preferred is false only while an open breaker is inside its delay. Once the
// delay elapses the node becomes preferable again *without* the read path
// touching the breaker: acquiring a trial permit here would burn the half-open
// budget on members that are merely being ranked, not dialed. Closing the
// breaker (Open→HalfOpen→Closed) happens in Observe / NoteProbe.
func (s *Store) Score(tag string) (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Disabled {
		return 0, true // all equal => pure latency ordering, i.e. stock sing-box
	}
	st := s.stats[normalizeTag(tag)]
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
	switch {
	case st.breaker.IsOpen():
		// failsafe-go stays in Open until the next TryAcquirePermit after the
		// delay (Observe/NoteProbe). RemainingDelay==0 with IsOpen is "awaiting
		// trial", not a permanent ban — surface it as half-open so the UI
		// matches reality. Use the duration (not truncated seconds) so a 400ms
		// remainder still reads as open, not half-open.
		remDur := st.breaker.RemainingDelay()
		if remDur > 0 {
			rem := int((remDur + time.Second - 1) / time.Second) // ceil
			if rem < 1 {
				rem = 1
			}
			return "open", rem
		}
		return "half-open", 0
	case st.breaker.IsHalfOpen():
		return "half-open", 0
	default:
		return "closed", 0
	}
}

// blackholedLocked reports whether a node is currently a confirmed blackhole.
// The streak is the state; BlackholedAt only records when it was confirmed, so
// a single byte received anywhere clears it — recovery is immediate and does
// not wait out a timer, because a provider fixing a broken node is normal.
func (s *Store) blackholedLocked(st *Stats) bool {
	limit := s.cfg.Blackhole()
	return limit > 0 && st.BlackholeStreak >= limit
}

// scoreLocked computes the composite score. During warm-up every node reports
// the neutral 100 — all-equal scores collapse the ordering back to pure
// latency, which is exactly today's behaviour.
func (s *Store) scoreLocked(st *Stats) float64 {
	// A confirmed blackhole scores 0 even inside warm-up. Warm-up exists so a
	// node is not condemned on one unlucky dial; it is not a reason to keep
	// preferring a node that has proven it relays nothing. This is the one
	// signal conclusive enough to skip it — see RecordTransfer.
	if s.blackholedLocked(st) {
		return 0
	}
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
// throughputScore asks "how fast can this member go", so it reads the BEST
// sample in the window rather than the median.
//
// bytes/wall-clock is only a throughput measurement when the transfer was the
// thing taking the time. A streamed completion, an SSE channel or a long poll
// moves a few hundred KiB at the application's pace over minutes, and the same
// arithmetic reports single-digit KB/s for a link that is fine. Measured on a
// live gateway: every member's median sat at 1.7-94 KB/s while a bulk download
// through the selected one did 2500 KB/s, so throughput_score was ~5/100 for
// healthy and unhealthy members alike — 20% of the scale carrying no
// information, and a UI number that reads as "this node is terrible".
//
// The asymmetry is what makes max the right statistic: idleness can only bias a
// sample DOWN, while nothing can transfer faster than the link, so the largest
// observation is the closest thing to capacity that passive measurement can
// produce. One freak-high sample is bounded by the real rate; one idle
// connection is not bounded at all on the low side. "Is it behaving right now"
// is answered by reliability, latency and the breaker, not here, and the window
// is bounded (maxSeries) so a member that has genuinely slowed ages out.
func (s *Store) throughputScore(st *Stats) float64 {
	if len(st.ThroughputKBps) == 0 {
		return 50
	}
	kbps := maxFloat(st.ThroughputKBps)
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
		t = normalizeTag(t)
		if !scorable(t) || seen[t] {
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

		Blackhole:       s.blackholedLocked(st),
		BlackholeStreak: st.BlackholeStreak,

		LastOK:  st.LastOK,
		LastErr: st.LastErr,
	}
	if len(st.LatencyMS) > 0 {
		v.LatencyMS = medianInt(st.LatencyMS)
	}
	if len(st.ThroughputKBps) > 0 {
		// The same statistic throughputScore reads, so the badge and the number
		// behind it cannot disagree.
		v.ThroughputKBps = round1(maxFloat(st.ThroughputKBps))
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

// maxFloat returns the largest sample. See throughputScore for why throughput is
// read as a maximum and latency as a median.
func maxFloat(s []float64) float64 {
	out := s[0]
	for _, v := range s[1:] {
		if v > out {
			out = v
		}
	}
	return out
}

func medianFloat(s []float64) float64 {
	c := append([]float64(nil), s...)
	sort.Float64s(c)
	return c[len(c)/2]
}
