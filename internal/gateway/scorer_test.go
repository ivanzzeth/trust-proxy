package gateway

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/proxyscore"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
)

func newScoringManager(t *testing.T) *Manager {
	t.Helper()
	return NewManager(filepath.Join(t.TempDir(), "config.json"), t.TempDir(),
		whitelist.Rules{}, nil, "sekret", "")
}

// The scorer has to be in the context box.New is given, because every urltest
// group resolves it exactly once at construction. If a refactor moves the
// registration to after box.New — or drops it — nothing breaks loudly: the
// gateway comes up, serves traffic, and quietly ranks on latency alone forever.
func TestScorerIsRegisteredIntoTheBoxContext(t *testing.T) {
	m := newScoringManager(t)
	if got := service.FromContext[adapter.OutboundScorer](m.boxContext()); got == nil {
		t.Fatal("no OutboundScorer in the box context: urltest groups would rank on latency alone")
	}
}

// Disabled must mean absent, not "present but neutral". A scorer that is
// installed and returns 100 for everything still changes the tie-breaking path;
// the off switch has to restore upstream behaviour byte for byte.
func TestDisabledScoringLeavesTheContextClean(t *testing.T) {
	m := newScoringManager(t)
	m.applyScoring(proxygroups.Config{Scoring: proxyscore.Config{Disabled: true}})
	if got := service.FromContext[adapter.OutboundScorer](m.boxContext()); got != nil {
		t.Fatal("scoring is disabled but a scorer is still registered")
	}
}

// The store hangs off the Manager, not off the box. Applying a subscription
// rebuilds the instance; if the scores lived in it, adding one node would erase
// what the gateway had learned about every other node.
func TestScoresSurviveABoxRebuild(t *testing.T) {
	m := newScoringManager(t)
	sc := service.FromContext[adapter.OutboundScorer](m.boxContext())
	if sc == nil {
		t.Fatal("no scorer registered")
	}
	for i := 0; i < proxyscore.DefaultMinSamples; i++ {
		sc.Observe("node-a", false, 0, errors.New("dial failed"))
	}
	before, _ := sc.Score("node-a")
	if before >= 100 {
		t.Fatalf("ten failures should have moved the score off 100, got %v", before)
	}
	// A second context is what a rebuild produces.
	after, _ := service.FromContext[adapter.OutboundScorer](m.boxContext()).Score("node-a")
	if after != before {
		t.Fatalf("score changed across a rebuild: %v -> %v", before, after)
	}
}

// A rejected proxy-groups write reverts the groups; the scoring policy travelled
// inside that same config and has to revert with it, or the store stays tuned
// for a config the data plane refused.
func TestScoringRevertsWithTheGroupsItTravelledIn(t *testing.T) {
	m := newScoringManager(t)
	m.applyScoring(proxygroups.Config{Scoring: proxyscore.Config{MinSamples: 3}})
	if got := m.ScoringConfig().Samples(); got != 3 {
		t.Fatalf("min_samples = %d, want 3", got)
	}
	m.applyScoring(proxygroups.Config{})
	if got := m.ScoringConfig().Samples(); got != proxyscore.DefaultMinSamples {
		t.Fatalf("min_samples = %d after revert, want the default %d", got, proxyscore.DefaultMinSamples)
	}
}

// Errors cross the bridge as strings so the UI can say *why* a node is being
// avoided. "It is at 40" is a number; "TLS handshake timeout" is an answer.
func TestObserveCarriesTheErrorThrough(t *testing.T) {
	m := newScoringManager(t)
	sc := service.FromContext[adapter.OutboundScorer](m.boxContext())
	sc.Observe("node-a", false, 0, errors.New("handshake timeout"))
	views := m.Scores([]string{"node-a"})
	if len(views) != 1 || views[0].LastErr != "handshake timeout" {
		t.Fatalf("last_err not carried through: %+v", views)
	}
}

func TestRecordTransferFeedsTheThroughputTerm(t *testing.T) {
	m := newScoringManager(t)
	m.RecordTransfer("node-a", proxyscore.Transfer{Download: 8 << 20, Duration: 2 * time.Second})
	views := m.Scores([]string{"node-a"})
	if len(views) != 1 || views[0].ThroughputKBps <= 0 {
		t.Fatalf("throughput not recorded: %+v", views)
	}
}

// Snapshot lists every member asked about, including ones that have never
// carried traffic — a proxies page that only showed nodes with samples would
// hide exactly the nodes the user is wondering about.
func TestScoresListUnseenMembers(t *testing.T) {
	m := newScoringManager(t)
	views := m.Scores([]string{"never-used"})
	if len(views) != 1 || !views[0].Warming || views[0].Score != 100 {
		t.Fatalf("unseen member should be warming at 100: %+v", views)
	}
}
