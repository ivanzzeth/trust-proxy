package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
)

// Importing a catalog rule set must pick a source this machine can actually fetch
// from, not just the first one written down.
//
// `rules sets add <tag>` took the catalog's primary URL unless the caller thought to
// pass --mirror. On the machine that reported this, that primary delivered 54 KB to
// sing-box in 278 seconds while the mirror took 1.3 — so the default import was a
// five-minute box start, and the fix was a flag the person would have to already
// know they needed. A flag is not a fix for something the gateway can measure.
//
// --mirror still forces the mirror, and an explicit --url is still taken as given:
// somebody naming a source is not asking to be second-guessed.
func TestImportingFromTheCatalogPicksAReachableSource(t *testing.T) {
	dir := t.TempDir()
	rs, err := ruleset.NewStore(filepath.Join(dir, "rulesets.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{rs: rs, reach: unreachableExcept("cdn.jsdelivr.net")}

	entry, ok := ruleset.CatalogByTag("geoip-cn")
	if !ok {
		t.Skip("geoip-cn is not in the catalog")
	}

	r := httptest.NewRequest(http.MethodPost, "/api/rulesets",
		strings.NewReader(`{"catalog_tag":"geoip-cn"}`))
	rec := httptest.NewRecorder()
	s.handleAddRuleSet(rec, r)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("import failed: %d %s", rec.Code, rec.Body.String())
	}

	var got string
	for _, set := range rs.Get().Sets {
		if set.Tag == "geoip-cn" {
			got = set.URL
		}
	}
	if got == entry.URL {
		t.Fatalf("imported the primary source %s, which this machine cannot fetch from; "+
			"the mirror was available and the gateway could have measured that", got)
	}
	if !strings.Contains(got, "jsdelivr") {
		t.Fatalf("imported %q, want a jsdelivr mirror", got)
	}
}

// An explicit URL is the operator's decision and is not probed or replaced.
func TestImportingAnExplicitURLIsNotSecondGuessed(t *testing.T) {
	dir := t.TempDir()
	rs, err := ruleset.NewStore(filepath.Join(dir, "rulesets.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{rs: rs, reach: unreachableExcept("nothing-at-all")}

	r := httptest.NewRequest(http.MethodPost, "/api/rulesets", strings.NewReader(
		`{"tag":"mine","url":"https://my-mirror.example/mine.srs","format":"binary","role":"route-direct"}`))
	rec := httptest.NewRecorder()
	s.handleAddRuleSet(rec, r)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("import failed: %d %s", rec.Code, rec.Body.String())
	}
	for _, set := range rs.Get().Sets {
		if set.Tag == "mine" && set.URL != "https://my-mirror.example/mine.srs" {
			t.Fatalf("a hand-entered URL was rewritten to %s", set.URL)
		}
	}
}
