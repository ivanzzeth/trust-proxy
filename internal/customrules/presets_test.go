package customrules

import (
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Every preset must have a name, at least one RuleSet or Rule, and every rule
// must survive validation. RuleSet catalog tags must exist.
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
		if len(p.Rules) == 0 && len(p.RuleSets) == 0 {
			t.Fatalf("preset %q has neither rules nor rule_sets", p.Name)
		}
		for _, rs := range p.RuleSets {
			if rs.CatalogTag == "" {
				t.Fatalf("preset %q: empty catalog_tag", p.Name)
			}
			if _, ok := ruleset.CatalogByTag(rs.CatalogTag); !ok {
				t.Fatalf("preset %q: unknown catalog tag %q", p.Name, rs.CatalogTag)
			}
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
// (empty node); direct packs use the direct action. Rule-set-only packs have no
// per-rule exit to check (role comes from the catalog).
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

// Importing a preset's custom rules through the real store must keep every rule.
func TestPresets_ImportThroughStore(t *testing.T) {
	for _, p := range Presets {
		if len(p.Rules) == 0 {
			continue // rule-set-only packs (Google/Telegram/…) have nothing for the CR store
		}
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

// Google (and similar broad packs) must bind community geosite rule sets — not
// a hand-maintained gvt2/gvt3 domain table. That is the "stop playing whack-a-
// mole with companion domains" contract.
func TestPresets_GoogleBindsGeosite(t *testing.T) {
	var google *apitypes.PackPreset
	for i := range Presets {
		if Presets[i].Name == "Google" {
			google = &Presets[i]
			break
		}
	}
	if google == nil {
		t.Fatal("Google preset missing")
	}
	need := map[string]bool{"geosite-google": false, "geosite-youtube": false}
	for _, rs := range google.RuleSets {
		if _, ok := need[rs.CatalogTag]; ok {
			need[rs.CatalogTag] = true
		}
	}
	for tag, ok := range need {
		if !ok {
			t.Fatalf("Google preset missing rule_set %q", tag)
		}
	}
	if len(google.Rules) > 0 {
		t.Fatalf("Google should be rule-set-only (no hand domain list), got %d rules", len(google.Rules))
	}
}

// Catalog JSON must never emit "rules": null — the dashboard (and any client)
// treats Rules as an array and reads .length.
func TestPresets_RulesJSONNeverNull(t *testing.T) {
	for _, p := range Presets {
		if p.Rules == nil {
			t.Fatalf("preset %q has nil Rules (JSON would be null)", p.Name)
		}
	}
}

func TestPresets_XBindsTwitterGeosite(t *testing.T) {
	var x *apitypes.PackPreset
	for i := range Presets {
		if Presets[i].Name == "X" {
			x = &Presets[i]
			break
		}
	}
	if x == nil {
		t.Fatal("X preset missing")
	}
	if len(x.RuleSets) != 1 || x.RuleSets[0].CatalogTag != "geosite-twitter" {
		t.Fatalf("X should bind geosite-twitter, got %+v", x.RuleSets)
	}
	if _, ok := ruleset.CatalogByTag("geosite-twitter"); !ok {
		t.Fatal("geosite-twitter missing from rule-set catalog")
	}
}
