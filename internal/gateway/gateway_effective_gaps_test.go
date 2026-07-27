package gateway

import (
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// The view that explains "why is this blocked" must show the things that block.
//
// EffectiveRules never read the quarantine store, so destinations the gateway had
// blocked *itself* — the automatic-disposal list, injected into the same L1 floor
// as the blacklist — were invisible in the one screen built to answer that
// question. An operator looking for why a host is unreachable would find no rule
// mentioning it, and would go on to look everywhere else.
//
// Every existing test passed quarantine.List{}, so the drift test that compares
// this view with a freshly built config could not see the gap either.
func TestEffectiveRulesShowsQuarantine(t *testing.T) {
	m := &Manager{
		wl:      whitelist.Rules{Domains: []string{"example.com"}},
		quar:    quarantine.List{Entries: []quarantine.Entry{{Value: "c2.example", Reason: "threat-intel"}}},
		mode:    ModeManual,
		final:   "proxy",
		posture: apitypes.PostureStrict,
	}
	views := m.EffectiveRules()

	var found *apitypes.RuleView
	for i := range views {
		if strings.Contains(views[i].Source, "quarantine") {
			found = &views[i]
		}
	}
	if found == nil {
		t.Fatalf("nothing in the effective view mentions the quarantine, so a destination the "+
			"gateway blocked itself has no visible reason:\n%s", render(views))
	}
	if found.Layer != "L1" {
		t.Errorf("quarantine is shown at %s, but it is injected into the L1 floor", found.Layer)
	}
	if found.Action != "reject" {
		t.Errorf("quarantine action is %q, want reject", found.Action)
	}
	var mentions bool
	for _, v := range found.Values {
		if strings.Contains(v, "c2.example") {
			mentions = true
		}
	}
	if !mentions {
		t.Errorf("the quarantine row does not name the blocked destination: %v", found.Values)
	}
}

// Quarantine sits above the Permit gate, like the rest of the floor, and the view
// has to say so in the right order — the whole point of the layer labels is that
// somebody can read down them and predict the outcome.
func TestQuarantineAppearsAboveThePermitGate(t *testing.T) {
	m := &Manager{
		wl:      whitelist.Rules{Domains: []string{"example.com"}},
		quar:    quarantine.List{Entries: []quarantine.Entry{{Value: "c2.example"}}},
		mode:    ModeManual,
		final:   "proxy",
		posture: apitypes.PostureStrict,
	}
	views := m.EffectiveRules()
	quarIdx, gateIdx := -1, -1
	for i, v := range views {
		if strings.Contains(v.Source, "quarantine") && quarIdx < 0 {
			quarIdx = i
		}
		if v.Source == "permit-gate" {
			gateIdx = i
		}
	}
	if quarIdx < 0 || gateIdx < 0 {
		t.Fatalf("missing rows (quarantine=%d gate=%d):\n%s", quarIdx, gateIdx, render(views))
	}
	if quarIdx > gateIdx {
		t.Fatalf("quarantine is shown below the Permit gate, which reverses what the data plane " +
			"does — a quarantined destination is refused even when it is permitted")
	}
}

// A client-mode gateway does not enforce its own Permit gate: rebuild() forces
// Split, because two machines each running a default-deny of their own only fight.
// The view read the stored posture instead, so a client's Rules page showed a gate
// the data plane did not have — and a gate is the single most consequential thing
// on that page.
func TestClientModeViewDoesNotShowAGateItDoesNotHave(t *testing.T) {
	m := &Manager{
		wl:         whitelist.Rules{Domains: []string{"example.com"}},
		mode:       ModeManual,
		final:      "proxy",
		posture:    apitypes.PostureStrict, // what the store says
		clientMode: true,                   // what rebuild() actually does: Split
	}
	for _, v := range m.EffectiveRules() {
		if v.Source == "permit-gate" {
			t.Fatalf("a client-mode gateway's view shows a Permit gate:\n%s", render(m.EffectiveRules()))
		}
	}
}

func render(views []apitypes.RuleView) string {
	var b strings.Builder
	for _, v := range views {
		b.WriteString(v.Layer + " " + v.Source + " " + v.Action + " " + v.Matcher + " " +
			strings.Join(v.Values, ",") + "\n")
	}
	return b.String()
}
