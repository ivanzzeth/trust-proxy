package customrules

import (
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Every preset rule must survive validation (else importing a preset silently
// drops rules) and be tagged with its pack + enabled.
func TestPresets_AllRulesValidAndTagged(t *testing.T) {
	if len(Presets) == 0 {
		t.Fatal("no presets defined")
	}
	seenNames := map[string]bool{}
	for _, p := range Presets {
		if p.Name == "" {
			t.Fatal("preset with empty name")
		}
		if seenNames[p.Name] {
			t.Fatalf("duplicate preset name %q", p.Name)
		}
		seenNames[p.Name] = true
		if len(p.Rules) == 0 {
			t.Fatalf("preset %q has no rules", p.Name)
		}
		for _, r := range p.Rules {
			r := r
			if err := validate(&r); err != nil {
				t.Fatalf("preset %q rule %q: invalid: %v", p.Name, r.Value, err)
			}
			if r.Pack != p.Name {
				t.Fatalf("preset %q rule %q: pack=%q, want %q", p.Name, r.Value, r.Pack, p.Name)
			}
			if !r.Enabled {
				t.Fatalf("preset %q rule %q: not enabled", p.Name, r.Value)
			}
		}
	}
}

// A preset with a Region must pin every rule (proxy action) to that country's
// group tag; a preset without a Region must not pin any rule to a country group.
func TestPresets_RegionPinning(t *testing.T) {
	for _, p := range Presets {
		wantNode := ""
		if p.Region != "" {
			wantNode = proxygroups.CountryName(p.Region)
			if wantNode == p.Region {
				t.Fatalf("preset %q: region %q did not resolve to a country group tag", p.Name, p.Region)
			}
		}
		for _, r := range p.Rules {
			// Region packs pin proxy rules; direct/block rules (e.g. Apple) never pin.
			if r.Action == apitypes.CustomActionProxy && r.Node != wantNode {
				t.Fatalf("preset %q rule %q: node=%q, want %q (region %q)", p.Name, r.Value, r.Node, wantNode, p.Region)
			}
			if r.Action != apitypes.CustomActionProxy && r.Node != "" {
				t.Fatalf("preset %q rule %q: non-proxy action %q must not set node (%q)", p.Name, r.Value, r.Action, r.Node)
			}
		}
	}
}

// Importing a preset through the real store must keep every rule (proves the
// baked Node value passes the store's own validation path end to end).
func TestPresets_ImportThroughStore(t *testing.T) {
	for _, p := range Presets {
		s := newStore(t)
		for _, r := range p.Rules {
			if _, err := s.Add(r); err != nil {
				t.Fatalf("preset %q: store rejected rule %q: %v", p.Name, r.Value, err)
			}
		}
		got := s.Get()
		if len(got.Rules) != len(p.Rules) {
			t.Fatalf("preset %q: imported %d rules, want %d", p.Name, len(got.Rules), len(p.Rules))
		}
	}
}
