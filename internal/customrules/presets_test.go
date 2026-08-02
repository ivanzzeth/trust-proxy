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
			case apitypes.PackExitMixed:
				// Per-rule egress is intentional; only reject unknown actions.
				switch r.Action {
				case apitypes.CustomActionDirect, apitypes.CustomActionProxy, apitypes.CustomActionNode, apitypes.CustomActionBlock:
				default:
					t.Fatalf("preset %q (mixed) rule %q: unexpected action %q", p.Name, r.Value, r.Action)
				}
			case "":
				// Permit-only packs (e.g. China wide) have no Exit hint.
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

// Google binds community geosite rule sets for broad coverage, plus a small
// pinned login-host list so accounts.* / gstatic assets always take proxy
// ahead of China-direct (geosite overlap / missing entries caused sign-in RST).
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
	wantLogin := map[string]bool{
		"accounts.google.com": false, "accounts.youtube.com": false,
		"ssl.gstatic.com": false, "accounts.gstatic.com": false,
	}
	for _, r := range google.Rules {
		if r.Action != apitypes.CustomActionProxy {
			t.Fatalf("Google login pin %q must be proxy, got %s", r.Value, r.Action)
		}
		if _, ok := wantLogin[r.Value]; ok {
			wantLogin[r.Value] = true
		}
	}
	for d, ok := range wantLogin {
		if !ok {
			t.Fatalf("Google preset missing login pin %q", d)
		}
	}
}

func TestPresets_CursorCoversAgentNetwork(t *testing.T) {
	var cursor *apitypes.PackPreset
	for i := range Presets {
		if Presets[i].Name == "Cursor" {
			cursor = &Presets[i]
			break
		}
	}
	if cursor == nil {
		t.Fatal("Cursor preset missing")
	}
	if cursor.Exit != apitypes.PackExitMixed {
		t.Fatalf("Cursor exit=%q, want mixed (api5 direct + rest Overseas)", cursor.Exit)
	}
	want := map[string]bool{
		"api5.cursor.sh": false,
		"cursor.com":     false, "cursor.sh": false,
		"cursorapi.com": false, "cursor-cdn.com": false, "cursorvm.com": false,
		"todesktop.com": false,
	}
	api5Idx, cursorShIdx := -1, -1
	for i, r := range cursor.Rules {
		if _, ok := want[r.Value]; ok {
			want[r.Value] = true
		}
		switch r.Value {
		case "api5.cursor.sh":
			api5Idx = i
			if r.Action != apitypes.CustomActionDirect {
				t.Fatalf("api5.cursor.sh must be direct (Agent streams), got action=%q", r.Action)
			}
		case "cursor.sh":
			cursorShIdx = i
			if r.Action != apitypes.CustomActionProxy || r.Node != proxygroups.OverseasGroupTag {
				t.Fatalf("cursor.sh must be Overseas, got action=%q node=%q", r.Action, r.Node)
			}
		}
	}
	for d, ok := range want {
		if !ok {
			t.Fatalf("Cursor preset missing %q (needed under TUN for Agent/tools)", d)
		}
	}
	if api5Idx < 0 || cursorShIdx < 0 || api5Idx >= cursorShIdx {
		t.Fatalf("api5.cursor.sh (idx %d) must precede cursor.sh (idx %d); first match wins", api5Idx, cursorShIdx)
	}
}

func TestPresets_ChinaAxesSplit(t *testing.T) {
	var wide, direct *apitypes.PackPreset
	for i := range Presets {
		switch Presets[i].Name {
		case "China (wide)":
			wide = &Presets[i]
		case "China-direct":
			direct = &Presets[i]
		}
	}
	if wide == nil || direct == nil {
		t.Fatal("China (wide) and China-direct presets required")
	}
	if wide.Warning == "" {
		t.Fatal("China (wide) must warn about security trade-off")
	}
	if len(wide.RuleSets) != 1 || wide.RuleSets[0].Role != apitypes.RuleRolePermit {
		t.Fatalf("China (wide) should be permit-only geosite-cn, got %+v", wide.RuleSets)
	}
	if len(direct.RuleSets) != 1 || direct.RuleSets[0].Role != apitypes.RuleRoleRouteDirect {
		t.Fatalf("China-direct should be route-direct only, got %+v", direct.RuleSets)
	}
	merged := apitypes.MergeRuleRoles(wide.RuleSets[0].Role, direct.RuleSets[0].Role)
	if merged != apitypes.RuleRolePermitRouteDirect {
		t.Fatalf("both China packs should compose to permit+route-direct, got %q", merged)
	}
}
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

// Dev must cover Git SSH under TUN: domain hosts + git IP ranges (SSH dials by IP).
func TestPresets_DevCoversGitSSH(t *testing.T) {
	var dev *apitypes.PackPreset
	for i := range Presets {
		if Presets[i].Name == "Dev" {
			dev = &Presets[i]
			break
		}
	}
	if dev == nil {
		t.Fatal("Dev preset missing")
	}
	hasMSDev := false
	for _, rs := range dev.RuleSets {
		if rs.CatalogTag == "geosite-microsoft-dev" {
			hasMSDev = true
		}
	}
	if !hasMSDev {
		t.Fatal("Dev should bind geosite-microsoft-dev (VS Code / NuGet)")
	}
	hasSSH, hasGitCIDR, hasMetaIP, hasVSCode := false, false, false, false
	for _, r := range dev.Rules {
		switch {
		case r.Match == apitypes.CustomMatchDomainSuffix && r.Value == "ssh.github.com":
			hasSSH = true
		case r.Match == apitypes.CustomMatchDomainSuffix && r.Value == "code.visualstudio.com":
			hasVSCode = true
		case r.Match == apitypes.CustomMatchIPCIDR && r.Value == "140.82.112.0/20":
			hasGitCIDR = true
		case r.Match == apitypes.CustomMatchIPCIDR && r.Value == "20.205.243.160/32":
			hasMetaIP = true // the edge that closed our SSH kex in CN
		}
		if r.Match == apitypes.CustomMatchIPCIDR && r.Action != apitypes.CustomActionProxy {
			t.Fatalf("git CIDR %q must action=proxy, got %q", r.Value, r.Action)
		}
	}
	if !hasSSH {
		t.Fatal("Dev missing ssh.github.com domain rule")
	}
	if !hasVSCode {
		t.Fatal("Dev missing code.visualstudio.com (seen blocked in live history)")
	}
	if !hasGitCIDR {
		t.Fatal("Dev missing core GitHub git CIDR 140.82.112.0/20")
	}
	if !hasMetaIP {
		t.Fatal("Dev missing 20.205.243.160/32 (common CN git SSH edge)")
	}
}

// Telegram must include official DC CIDRs — live history showed thousands of
// IP-only blocks (91.108.56.125 / 149.154.171.5) with geosite domains alone.
func TestPresets_TelegramCoversOfficialCIDRs(t *testing.T) {
	var tg *apitypes.PackPreset
	for i := range Presets {
		if Presets[i].Name == "Telegram" {
			tg = &Presets[i]
			break
		}
	}
	if tg == nil {
		t.Fatal("Telegram preset missing")
	}
	need := map[string]bool{
		"91.108.56.0/22":     false,
		"149.154.160.0/20":   false,
		"2001:b28:f23f::/48": false,
	}
	for _, r := range tg.Rules {
		if r.Match != apitypes.CustomMatchIPCIDR {
			t.Fatalf("Telegram custom rules should be ip_cidr only, got %s=%s", r.Match, r.Value)
		}
		if _, ok := need[r.Value]; ok {
			need[r.Value] = true
		}
	}
	for cidr, ok := range need {
		if !ok {
			t.Fatalf("Telegram missing official CIDR %s from core.telegram.org/resources/cidr.txt", cidr)
		}
	}
}
