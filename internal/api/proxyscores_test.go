package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/proxyscore"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

type fakeScorer struct {
	views    []proxyscore.View
	cfg      proxyscore.Config
	resetted bool
}

func (f *fakeScorer) Scores(tags []string) []proxyscore.View { return f.views }
func (f *fakeScorer) ScoringConfig() proxyscore.Config       { return f.cfg }
func (f *fakeScorer) ResetScores()                           { f.resetted = true }
func (f *fakeScorer) NoteProbe(string, bool, time.Duration)  {}

func getScores(t *testing.T, s *Server) apitypes.ProxyScores {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleGetProxyScores(rec, httptest.NewRequest(http.MethodGet, "/api/proxy-scores", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out apitypes.ProxyScores
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The response has to be readable as the ranking itself. A demoted node with a
// high stale score must not sit at the top of a table the operator reads as
// "what the gateway will pick next" — that reads as a lie about the data plane.
func TestProxyScoresSortDemotedLast(t *testing.T) {
	s := &Server{scorer: &fakeScorer{views: []proxyscore.View{
		{Tag: "b-mid", Score: 60, Preferred: true},
		{Tag: "a-open", Score: 99, Preferred: false, Breaker: "open"},
		{Tag: "c-best", Score: 88, Preferred: true},
		{Tag: "d-tie", Score: 88, Preferred: true},
	}}}

	out := getScores(t, s)
	var order []string
	for _, sc := range out.Scores {
		order = append(order, sc.Tag)
	}
	want := []string{"c-best", "d-tie", "b-mid", "a-open"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("sort: got %v want %v", order, want)
		}
	}
}

// "Why is this node at 62" must be answerable from this one response: the
// config comes back fully resolved (no zero values the caller has to know the
// defaults for) and the formula is rendered with the weights actually in force.
func TestProxyScoresExplainThemselves(t *testing.T) {
	s := &Server{scorer: &fakeScorer{
		views: []proxyscore.View{{Tag: "n1", Score: 100, Warming: true, MinSamples: 10}},
	}}

	out := getScores(t, s)
	if !out.Enabled {
		t.Fatal("expected enabled when config is not disabled")
	}
	if out.Formula == "" {
		t.Fatal("formula must be rendered server-side, or every client re-implements the arithmetic")
	}
	// An all-zero stored config must render as the values in force, not as a row
	// of blanks the user has to know the defaults for.
	if out.Config.MinSamples == 0 || out.Config.WeightReliability == 0 ||
		out.Config.BreakerDelaySeconds == 0 || out.Config.StaleHours == 0 {
		t.Fatalf("config must come back resolved, got %+v", out.Config)
	}
	if !out.Scores[0].Warming || out.Scores[0].MinSamples != 10 {
		t.Fatalf("warm-up state must survive the wire: %+v", out.Scores[0])
	}
}

// A weight the user deliberately set to 0 ("ignore throughput") must not be
// mistaken for "unset" and refilled with the default — that would silently put
// back a term they turned off.
func TestProxyScoresKeepDeliberateZeroWeights(t *testing.T) {
	s := &Server{scorer: &fakeScorer{cfg: proxyscore.Config{WeightReliability: 30, WeightLatency: 70}}}
	out := getScores(t, s)
	if out.Config.WeightLatency != 70 || out.Config.WeightReliability != 30 || out.Config.WeightThroughput != 0 {
		t.Fatalf("weights not preserved: %+v", out.Config)
	}
}

func TestProxyScoresUnavailableWithoutScorer(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleGetProxyScores(rec, httptest.NewRequest(http.MethodGet, "/api/proxy-scores", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.handleResetProxyScores(rec, httptest.NewRequest(http.MethodPost, "/api/proxy-scores/reset", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestResetProxyScores(t *testing.T) {
	f := &fakeScorer{}
	s := &Server{scorer: f}
	rec := httptest.NewRecorder()
	s.handleResetProxyScores(rec, httptest.NewRequest(http.MethodPost, "/api/proxy-scores/reset", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !f.resetted {
		t.Fatal("reset did not reach the store")
	}
}
