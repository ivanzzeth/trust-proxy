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

// The Exit hint must match how the rules actually egress: overseas packs route
// every proxy rule through the Overseas group; auto packs use the default proxy
// (empty node); direct packs use the direct action.
func TestPresets_ExitMatchesRules(t *testing.T) {
	for _, p := range Presets {
		for _, r := range p.Rules {
			switch p.Exit {
			case apitypes.PackExitOverseas:
				if r.Action != apitypes.CustomActionProxy || r.Node != proxygroups.OverseasGroupTag {
					t.Fatalf("preset %q (overseas) rule %q: action=%q node=%q, want proxy -> %q", p.Name, r.Value, r.Action, r.Node, proxygroups.OverseasGroupTag)
				}
			case apitypes.PackExitAuto:
				if r.Action != apitypes.CustomActionProxy || r.Node != "" {
					t.Fatalf("preset %q (auto) rule %q: action=%q node=%q, want proxy with no node", p.Name, r.Value, r.Action, r.Node)
				}
			case apitypes.PackExitDirect:
				if r.Action != apitypes.CustomActionDirect || r.Node != "" {
					t.Fatalf("preset %q (direct) rule %q: action=%q node=%q, want direct", p.Name, r.Value, r.Action, r.Node)
				}
			default:
				t.Fatalf("preset %q: unknown Exit %q", p.Name, p.Exit)
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
