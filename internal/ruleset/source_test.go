package ruleset

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// The catalog has always carried a mirror; the seed only ever read the primary.
func TestSourcesOffersTheMirrorsAsWellAsGitHub(t *testing.T) {
	e := apitypes.RuleSetCatalogEntry{
		Tag:    "geoip-cn",
		URL:    "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
		Mirror: "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs",
	}
	got := Sources(e)
	if len(got) < 3 {
		t.Fatalf("only %d source(s): %v — a machine that cannot reach GitHub has nowhere to go", len(got), got)
	}
	if got[0] != e.Mirror {
		t.Fatalf("the jsdelivr mirror should come first (both reachable → avoid GitHub stall), got %q", got[0])
	}
	if got[len(got)-1] != e.URL {
		t.Fatalf("GitHub primary should be last fallback, got last=%q", got[len(got)-1])
	}
	var mirrors int
	for _, u := range got {
		if strings.Contains(u, "jsdelivr.net") {
			mirrors++
		}
		if !strings.HasSuffix(u, "geoip-cn.srs") {
			t.Fatalf("a derived source lost the path: %q", u)
		}
	}
	if mirrors < 2 {
		t.Fatalf("expected several jsdelivr front-ends, got %d: %v", mirrors, got)
	}
}

// A box already pointing at raw.githubusercontent must still be rewritten when a
// mirror answers — ResolveSources used to only touch rs.URL == catalog primary,
// so a stalled GitHub URL never healed once it was already "the primary".
func TestResolveSourcesRewritesAnyCatalogSourceURL(t *testing.T) {
	entry, ok := CatalogByTag("geosite-cn")
	if !ok || entry.Mirror == "" {
		t.Skip("catalog changed")
	}
	sets := []apitypes.RuleSet{
		{Tag: entry.Tag, Type: "remote", URL: entry.URL, Enabled: true},
	}
	disabled := ResolveSourcesWith(sets, func(probe map[string]string) map[string]bool {
		out := map[string]bool{}
		for h := range probe {
			out[h] = strings.Contains(h, "jsdelivr.net")
		}
		return out
	})
	if len(disabled) != 0 {
		t.Fatalf("mirror was reachable; should not disable: %v", disabled)
	}
	if !strings.Contains(sets[0].URL, "jsdelivr") {
		t.Fatalf("still on %q — expected rewrite to a jsdelivr mirror", sets[0].URL)
	}
}

// A blackholed candidate must not cost the whole budget: the point of racing is
// that four dead hosts in sequence would stall a posture switch for a minute.
func TestPickReachableTakesTheOneThatAnswers(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("x"))
	}))
	defer ok.Close()
	dead := "http://127.0.0.1:1/nope.srs" // nothing listens on port 1

	start := time.Now()
	got := PickReachable([]string{dead, ok.URL + "/geoip-cn.srs"}, 8*time.Second)
	if got == "" {
		t.Fatal("a reachable candidate was reported unreachable")
	}
	if !strings.HasPrefix(got, ok.URL) {
		t.Fatalf("picked %q, want the one that answers", got)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("waited %s — the candidates are not being raced", time.Since(start))
	}

	if got := PickReachable([]string{dead}, 2*time.Second); got != "" {
		t.Fatalf("nothing is reachable, got %q", got)
	}
	// A 404 is an answer, but not one worth pointing sing-box at.
	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer missing.Close()
	if got := PickReachable([]string{missing.URL}, 2*time.Second); got != "" {
		t.Fatalf("a 404 was treated as reachable: %q", got)
	}
}

// Unreachable rule sets are disabled, never dropped: injectRuleSets skips
// disabled ones so the box still starts, and the entry stays visible to be
// enabled once there is a node.
func TestResolveSourcesDisablesWhatItCannotReach(t *testing.T) {
	entry, ok := CatalogByTag("geoip-cn")
	if !ok {
		t.Skip("catalog changed")
	}
	sets := []apitypes.RuleSet{
		{Tag: entry.Tag, Type: "remote", URL: entry.URL, Enabled: true},
		{Tag: "mine", Type: "remote", URL: "http://127.0.0.1:1/x.srs", Enabled: true},
		{Tag: "local-one", Type: "local", Enabled: true},
	}
	// A zero budget makes every probe fail, which is the offline case.
	disabled := ResolveSources(sets, time.Millisecond)

	if len(disabled) != 1 || disabled[0] != entry.Tag {
		t.Fatalf("disabled = %v, want just the catalog entry", disabled)
	}
	if sets[0].Enabled {
		t.Fatal("an unreachable catalog rule set stayed enabled — the box would refuse to start")
	}
	if sets[0].URL == "" {
		t.Fatal("the URL was cleared; it has to stay so enabling it later works")
	}
	// Somebody's own URL is theirs, reachable or not.
	if !sets[1].Enabled {
		t.Fatal("a hand-entered rule set was disabled")
	}
	if !sets[2].Enabled {
		t.Fatal("a local rule set was touched; it has nothing to download")
	}
}
