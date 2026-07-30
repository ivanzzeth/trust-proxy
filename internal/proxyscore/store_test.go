package proxyscore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "proxyscores.json"), cfg)
}

func observeN(s *Store, tag string, n int, ok bool, lat time.Duration) {
	for i := 0; i < n; i++ {
		s.Observe(tag, Outcome{Success: ok, Latency: lat})
	}
}

// The user's rule: every node starts at 100 and only produces a real score once
// it has MinSamples outcomes. A node that is failing hard must still read 100
// while warming — otherwise a network blip during startup demotes everything.
func TestWarmUpHoldsNeutralScore(t *testing.T) {
	s := newTestStore(t, Config{})
	for i := 1; i < DefaultMinSamples; i++ {
		s.Observe("bad", Outcome{Success: false, Err: "refused"})
		if got, _ := s.Score("bad"); got != 100 {
			t.Fatalf("sample %d: score = %v, want 100 while warming", i, got)
		}
	}
	// The MinSamples-th outcome is the one that publishes a real score.
	s.Observe("bad", Outcome{Success: false, Err: "refused"})
	got, _ := s.Score("bad")
	if got >= 100 {
		t.Fatalf("after %d failures score = %v, want a real (lower) score", DefaultMinSamples, got)
	}
	v := s.Snapshot(nil)[0]
	if v.Warming {
		t.Fatalf("still warming after %d samples", DefaultMinSamples)
	}
}

// An unknown tag scores the neutral 100 — a node that has never been dialed is
// not evidence of anything.
func TestUnknownTagIsNeutral(t *testing.T) {
	s := newTestStore(t, Config{})
	score, preferred := s.Score("never-seen")
	if score != 100 || !preferred {
		t.Fatalf("unknown tag = (%v, %v), want (100, true)", score, preferred)
	}
}

// "对连续的失败增加惩罚力度，对连续的成功增加奖励力度": the Nth consecutive
// failure must cost strictly more than the first. An average would not.
func TestStreakAmplifiesPenaltyAndReward(t *testing.T) {
	s := newTestStore(t, Config{})
	s.Observe("n", Outcome{Success: false})
	s.mu.Lock()
	first := 100 - s.stats["n"].Reliability
	s.mu.Unlock()
	if first <= 0 {
		t.Fatalf("first failure cost %v points, want > 0", first)
	}

	s.Observe("n", Outcome{Success: false})
	s.mu.Lock()
	st := s.stats["n"]
	second := (100 - first) - st.Reliability
	streak := st.FailStreak
	s.mu.Unlock()
	if second <= first {
		t.Fatalf("second consecutive failure cost %v, want more than the first (%v)", second, first)
	}
	if streak != 2 {
		t.Fatalf("fail streak = %d, want 2", streak)
	}

	// A success resets the failure streak, and consecutive successes ramp up too.
	s.Observe("n", Outcome{Success: true, Latency: 10 * time.Millisecond})
	s.mu.Lock()
	base := s.stats["n"].Reliability
	if s.stats["n"].FailStreak != 0 {
		t.Fatalf("fail streak not reset after a success")
	}
	s.mu.Unlock()
	s.Observe("n", Outcome{Success: true, Latency: 10 * time.Millisecond})
	s.mu.Lock()
	gain2 := s.stats["n"].Reliability - base
	s.mu.Unlock()
	if gain2 <= float64(DefaultRewardPerSuccess) {
		t.Fatalf("second consecutive success gained %v, want more than a single reward (%d)", gain2, DefaultRewardPerSuccess)
	}
}

// The streak multiplier is capped, otherwise a node that has been down for an
// hour would take an hour of successes to climb back.
func TestStreakIsCapped(t *testing.T) {
	s := newTestStore(t, Config{MaxStreak: 3, PenaltyPerFailure: 1, RewardPerSuccess: 1})
	observeN(s, "n", 20, false, 0)
	s.mu.Lock()
	streak := s.stats["n"].FailStreak
	s.mu.Unlock()
	if streak != 20 {
		t.Fatalf("streak counter = %d, want 20 (the counter itself is uncapped, only its effect is)", streak)
	}
	// Recovering must not require 20 successes: with the cap, each success is
	// worth up to MaxStreak points.
	observeN(s, "n", 12, true, 5*time.Millisecond)
	s.mu.Lock()
	rel := s.stats["n"].Reliability
	s.mu.Unlock()
	if rel <= 0 {
		t.Fatalf("reliability still %v after 12 successes; the cap is not working", rel)
	}
}

// Two nodes with the same score must be ordered by latency — the data plane
// does that ordering, but the store has to actually differentiate them, which
// it can only do once both are out of warm-up.
func TestEqualScoresDifferByLatency(t *testing.T) {
	s := newTestStore(t, Config{})
	observeN(s, "fast", DefaultMinSamples, true, 20*time.Millisecond)
	observeN(s, "slow", DefaultMinSamples, true, 700*time.Millisecond)
	fast, _ := s.Score("fast")
	slow, _ := s.Score("slow")
	if fast <= slow {
		t.Fatalf("fast=%v slow=%v, want the low-latency node to score higher", fast, slow)
	}
}

// The breaker is what stops a dead node from riding its warm-up 100 into
// selection: it works from sample #1, well before any score exists.
func TestBreakerOpensDuringWarmUp(t *testing.T) {
	s := newTestStore(t, Config{BreakerFailures: 3, BreakerDelaySeconds: 60})
	observeN(s, "dead", 3, false, 0)
	score, preferred := s.Score("dead")
	if score != 100 {
		t.Fatalf("score = %v, want 100 (still warming)", score)
	}
	if preferred {
		t.Fatal("breaker did not open during warm-up: a dead node would be picked at 100 points")
	}
	v := s.Snapshot(nil)[0]
	if v.Breaker != "open" || v.BreakerRemaining <= 0 {
		t.Fatalf("snapshot breaker = %q remaining=%d, want open with a countdown", v.Breaker, v.BreakerRemaining)
	}
}

// An open breaker must only demote, never exclude. This is the guard against
// repeating the incident in urltest_cooldown_test.go, where every member being
// excluded at once left the gateway with no egress at all.
func TestOpenBreakerStillReportsAScore(t *testing.T) {
	s := newTestStore(t, Config{BreakerFailures: 2, BreakerDelaySeconds: 60})
	observeN(s, "dead", DefaultMinSamples, false, 0)
	score, preferred := s.Score("dead")
	if preferred {
		t.Fatal("breaker should be open")
	}
	if score < 0 || score > 100 {
		t.Fatalf("score = %v, want a usable 0..100 value even with the breaker open", score)
	}
	// The node must still be listed — an invisible banned node is unfixable.
	found := false
	for _, v := range s.Snapshot(nil) {
		if v.Tag == "dead" {
			found = true
		}
	}
	if !found {
		t.Fatal("node with an open breaker vanished from the snapshot")
	}
}

// Recovery: once the delay elapses the node is preferable again without the
// read path burning a half-open permit, and a real success closes the breaker.
func TestBreakerRecovers(t *testing.T) {
	// 1s is the shortest delay the config exposes (whole seconds); 0 would
	// resolve to the 30s default.
	s := New(filepath.Join(t.TempDir(), "s.json"), Config{BreakerFailures: 2, BreakerSuccesses: 1, BreakerDelaySeconds: 1})
	observeN(s, "n", 2, false, 0)
	if _, preferred := s.Score("n"); preferred {
		t.Fatal("breaker should be open right after the failures")
	}
	time.Sleep(1100 * time.Millisecond)
	if _, preferred := s.Score("n"); !preferred {
		t.Fatal("after the delay elapsed the node should be preferable again")
	}
	s.Observe("n", Outcome{Success: true, Latency: 10 * time.Millisecond})
	v := s.Snapshot(nil)[0]
	if v.Breaker == "open" {
		t.Fatalf("breaker still open after a successful dial past the delay: %+v", v)
	}
}

// Reading the score must never consume a half-open trial permit: ranking is not
// dialing, and burning the budget would starve the one connection that is
// supposed to test recovery.
func TestScoreDoesNotConsumeHalfOpenPermits(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "s.json"), Config{BreakerFailures: 2, BreakerSuccesses: 2, BreakerDelaySeconds: 1})
	observeN(s, "n", 2, false, 0)
	time.Sleep(1100 * time.Millisecond)
	for i := 0; i < 50; i++ {
		s.Score("n") // a busy group ranks constantly
	}
	// Two real successes must still be enough to close it.
	s.Observe("n", Outcome{Success: true, Latency: time.Millisecond})
	s.Observe("n", Outcome{Success: true, Latency: time.Millisecond})
	v := s.Snapshot(nil)[0]
	if v.Breaker != "closed" {
		t.Fatalf("breaker = %q after two successes, want closed (Score() ate the trial permits)", v.Breaker)
	}
}

// direct/block are policy outcomes, not nodes; scoring them would be noise.
func TestPseudoOutboundsIgnored(t *testing.T) {
	s := newTestStore(t, Config{})
	for _, tag := range []string{"direct", "block", "blocked", ""} {
		observeN(s, tag, 5, false, 0)
		s.RecordTransfer(tag, 10<<20, time.Second)
	}
	if got := len(s.Snapshot(nil)); got != 0 {
		t.Fatalf("snapshot has %d entries, want 0", got)
	}
}

// A tiny transfer is a small request, not a slow node.
func TestThroughputIgnoresTinyTransfers(t *testing.T) {
	s := newTestStore(t, Config{})
	s.RecordTransfer("n", 1024, time.Second)
	if len(s.Snapshot(nil)) != 0 {
		t.Fatal("a 1KB transfer created a throughput sample")
	}
	s.RecordTransfer("n", 8<<20, time.Second)
	v := s.Snapshot(nil)[0]
	if v.ThroughputKBps <= 0 {
		t.Fatalf("throughput not recorded for an 8MB transfer: %+v", v)
	}
}

// Persistence: scores survive a restart (box rebuilds are frequent), but
// anything older than StaleHours is discarded — after a subscription or network
// change the old numbers describe a different path.
func TestPersistenceAndStaleExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxyscores.json")

	s := New(path, Config{})
	observeN(s, "fresh", DefaultMinSamples, true, 30*time.Millisecond)
	observeN(s, "old", DefaultMinSamples, true, 30*time.Millisecond)
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}

	// Backdate "old" past the staleness window.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Stats []*Stats `json:"stats"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, st := range doc.Stats {
		if st.Tag == "old" {
			st.UpdatedAt = time.Now().Add(-time.Duration(DefaultStaleHours+1) * time.Hour)
		}
	}
	nb, _ := json.Marshal(map[string]any{"stats": doc.Stats})
	if err := os.WriteFile(path, nb, 0o600); err != nil {
		t.Fatal(err)
	}

	s2 := New(path, Config{})
	views := s2.Snapshot(nil)
	if len(views) != 1 || views[0].Tag != "fresh" {
		t.Fatalf("after reload got %+v, want only the fresh entry", views)
	}
	if views[0].Samples != DefaultMinSamples {
		t.Fatalf("samples = %d, want the persisted %d", views[0].Samples, DefaultMinSamples)
	}
	if views[0].Warming {
		t.Fatal("a restored node should not be back in warm-up; the restart would re-learn from scratch")
	}
}

// A corrupt file must never stop the gateway from booting.
func TestCorruptFileIsNotFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(path, Config{})
	if got, _ := s.Score("n"); got != 100 {
		t.Fatalf("score = %v after a corrupt load, want the neutral 100", got)
	}
}

// Disabled scoring must be indistinguishable from stock sing-box: every node
// reports the same score, so ordering collapses to pure latency.
func TestDisabledIsNeutral(t *testing.T) {
	s := newTestStore(t, Config{Disabled: true})
	observeN(s, "a", 50, false, 0)
	a, prefA := s.Score("a")
	b, prefB := s.Score("b")
	if a != b || !prefA || !prefB {
		t.Fatalf("disabled scoring differentiates nodes: a=(%v,%v) b=(%v,%v)", a, prefA, b, prefB)
	}
}

// Changing a weight must not reset an open breaker — that would hand a dead
// node straight back to the dialer on a settings save.
func TestSetConfigKeepsBreakerUnlessBreakerParamsChange(t *testing.T) {
	s := newTestStore(t, Config{BreakerFailures: 2, BreakerDelaySeconds: 60})
	observeN(s, "dead", 2, false, 0)
	if _, pref := s.Score("dead"); pref {
		t.Fatal("breaker should be open")
	}
	s.SetConfig(Config{BreakerFailures: 2, BreakerDelaySeconds: 60, WeightLatency: 90, WeightReliability: 5, WeightThroughput: 5})
	if _, pref := s.Score("dead"); pref {
		t.Fatal("a weight change reset the open breaker")
	}
	s.SetConfig(Config{BreakerFailures: 9, BreakerDelaySeconds: 60})
	if _, pref := s.Score("dead"); !pref {
		t.Fatal("changing the breaker's own parameters should rebuild it")
	}
}

// Snapshot lists group members that have never been dialed, so the console
// shows the whole group rather than only the nodes with observations.
func TestSnapshotIncludesUnseenTags(t *testing.T) {
	s := newTestStore(t, Config{})
	observeN(s, "seen", 3, true, 10*time.Millisecond)
	views := s.Snapshot([]string{"seen", "unseen"})
	if len(views) != 2 {
		t.Fatalf("got %d views, want 2", len(views))
	}
	for _, v := range views {
		if v.Tag == "unseen" && (!v.Warming || v.Score != 100) {
			t.Fatalf("unseen node = %+v, want warming at 100", v)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	bad := []Config{
		{MinSamples: -1},
		{LatencyGoodMS: 900, LatencyBadMS: 100},
		{PenaltyPerFailure: 500},
		{StaleHours: 10000},
		{BreakerDelaySeconds: 99999},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("case %d: %+v accepted, want rejection", i, c)
		}
	}
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("zero config rejected: %v", err)
	}
	zero := Config{}
	r := zero.Resolved()
	if r.MinSamples != DefaultMinSamples || r.WeightReliability != DefaultWeightReliability {
		t.Fatalf("Resolved() left fields unset: %+v", r)
	}
	if zero.Formula() == "" {
		t.Fatal("empty formula")
	}
}
