package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/posture"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// A Split slot that was seeded once with sources this machine cannot reach must be
// recoverable by trying again.
//
// The mirror selection ran behind `!toSlot.Seeded`, and the slot is persisted
// *before* the apply that might fail. So the first attempt wrote a slot full of
// raw.githubusercontent.com URLs, marked it seeded, and then failed to start the
// box on them — and every retry afterwards skipped the resolution entirely and
// failed on exactly the same URLs. Reported from a real machine: five rule sets,
// all `context deadline exceeded`, and no sequence of commands that could fix it.
//
// "Retrying cannot help" is the worst property a failure can have, because
// retrying is what everybody does.
func TestSwitchingToSplitReResolvesAnAlreadySeededSlot(t *testing.T) {
	dir := t.TempDir()
	store, err := posture.NewStore(filepath.Join(dir, "posture.json"))
	if err != nil {
		t.Fatal(err)
	}

	// The state their machine was in: seeded, with primary URLs, from an attempt that
	// then failed to apply.
	seeded := posture.SeedSplit()
	if len(seeded.RuleSets) == 0 {
		t.Fatal("SeedSplit produced no rule sets; this test would prove nothing")
	}
	for i := range seeded.RuleSets {
		if entry, ok := ruleset.CatalogByTag(seeded.RuleSets[i].Tag); ok {
			seeded.RuleSets[i].URL = entry.URL // the primary, un-mirrored source
		}
	}
	if err := store.PutSlot(apitypes.PostureSplit, seeded); err != nil {
		t.Fatal(err)
	}

	slot, err := store.Slot(apitypes.PostureSplit)
	if err != nil {
		t.Fatal(err)
	}
	if !slot.Seeded {
		t.Fatal("the slot should read as seeded")
	}

	// What the handler must do now: resolve again, even though it is seeded.
	before := slot.RuleSets[0].URL
	resolved, _ := resolveSlotSources(slot.RuleSets, unreachableExcept("cdn.jsdelivr.net"))
	if !resolved {
		t.Fatal("nothing was rewritten on an already-seeded slot")
	}
	after := slot.RuleSets[0].URL
	if after == before {
		t.Fatalf("the URL is unchanged (%s): a seeded slot is never re-resolved, so a machine "+
			"that failed once can never succeed", after)
	}
}

// Re-resolving must not undo a URL the operator typed themselves. ResolveSources
// already only touches sets whose URL still matches the catalog's; this pins it,
// because running on every switch instead of once makes the blast radius bigger.
func TestReResolvingLeavesAHandEnteredURLAlone(t *testing.T) {
	sets := []apitypes.RuleSet{{
		Tag: "geoip-cn", Type: "remote", Format: "binary",
		URL:  "https://my-own-mirror.example/geoip-cn.srs",
		Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true,
	}}
	resolveSlotSources(sets, unreachableExcept("cdn.jsdelivr.net"))
	if sets[0].URL != "https://my-own-mirror.example/geoip-cn.srs" {
		t.Fatalf("a hand-entered URL was rewritten to %s", sets[0].URL)
	}
}

// unreachableExcept is a probe stand-in: only the named host answers. Injecting it
// is the point — the real probe reaches the network, and a test that did would be
// measuring GitHub's availability rather than this code.
func unreachableExcept(host string) func(map[string]string) map[string]bool {
	return func(probe map[string]string) map[string]bool {
		out := map[string]bool{}
		for h := range probe {
			out[h] = h == host
		}
		return out
	}
}

// The same claim, through the handler, because that is where the bug was: the
// resolution sat behind `!toSlot.Seeded`, and a helper test cannot see a condition
// in its caller. The first version of this file only tested the helper and stayed
// green when the handler condition was put back — which is the same trap as a
// green shape test over a config that will not start.
func TestHandleSetPostureReResolvesAnAlreadySeededSlot(t *testing.T) {
	s := newLivePolicyServer(t)
	dir := t.TempDir()
	store, err := posture.NewStore(filepath.Join(dir, "posture.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.posture = store
	s.profApplier = &fakeProfileApplier{}
	// Only the mirror answers, which is the shape of the machine this came from:
	// the primary times out where sing-box dials it.
	s.reach = unreachableExcept("cdn.jsdelivr.net")

	// The state that machine was in: seeded, primary URLs, from an attempt that then
	// failed to apply (the slot is written before the apply).
	seeded := posture.SeedSplit()
	for i := range seeded.RuleSets {
		if entry, ok := ruleset.CatalogByTag(seeded.RuleSets[i].Tag); ok {
			seeded.RuleSets[i].URL = entry.URL
		}
	}
	if err := store.PutSlot(apitypes.PostureSplit, seeded); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPut, "/api/posture", strings.NewReader(`{"active":"split"}`))
	rec := httptest.NewRecorder()
	s.handleSetPosture(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("switching to split failed: %d %s", rec.Code, rec.Body.String())
	}

	after, err := store.Slot(apitypes.PostureSplit)
	if err != nil {
		t.Fatal(err)
	}
	var onPrimary []string
	for _, rs := range after.RuleSets {
		if rs.Enabled && strings.Contains(rs.URL, "raw.githubusercontent.com") {
			onPrimary = append(onPrimary, rs.Tag)
		}
	}
	if len(onPrimary) > 0 {
		t.Fatalf("an already-seeded slot was not re-resolved: %v still point at the primary "+
			"source this machine cannot fetch from, so every retry fails identically", onPrimary)
	}
}
