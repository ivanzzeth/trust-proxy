package customrules

import (
	"strings"
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
			case apitypes.PackExitPinned:
				// The point of a pinned pack is that every rule leaves through
				// the SAME country. A rule that lost its Node (or that names
				// the roaming Overseas group) puts the pack back on a
				// latency-ranked exit that spans a dozen countries — the exact
				// failure this exit kind exists to prevent.
				if r.Action != apitypes.CustomActionProxy || r.Node == "" || r.Node == proxygroups.OverseasGroupTag {
					t.Fatalf("preset %q (pinned) rule %q: action=%q node=%q, want proxy -> a country group", p.Name, r.Value, r.Action, r.Node)
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
		t.Fatalf("Cursor exit=%q, want mixed (api5 direct + rest pinned)", cursor.Exit)
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
			if r.Action != apitypes.CustomActionProxy || r.Node != usTag {
				t.Fatalf("cursor.sh must be pinned to %q, got action=%q node=%q", usTag, r.Action, r.Node)
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

// aiPacks are the packs whose traffic is account-bound: the service ties the
// session to where it came from, so a roaming exit costs you a re-auth loop or
// a region block. They must each pin exactly one country.
var aiPacks = []string{"Claude", "OpenAI", "Cursor", "AI (other)"}

func presetByName(t *testing.T, name string) *apitypes.PackPreset {
	t.Helper()
	for i := range Presets {
		if Presets[i].Name == name {
			return &Presets[i]
		}
	}
	t.Fatalf("preset %q missing", name)
	return nil
}

// Every AI pack sends all of its proxied traffic to ONE country group. This is
// the regression that started it: the packs used to target the shared Overseas
// urltest, which ranks ~all non-HK/CN nodes by latency. On a real subscription
// that was 26 nodes across 14 countries (TR/VN/PH/TH/MY included), and one
// logged-in ChatGPT session was measured dialling from GB, KR, SG and VN inside
// a single week. Two countries in one pack is the same bug, just smaller.
func TestPresets_AIPacksPinExactlyOneCountry(t *testing.T) {
	for _, name := range aiPacks {
		p := presetByName(t, name)
		nodes := map[string]bool{}
		for _, r := range p.Rules {
			if r.Action != apitypes.CustomActionProxy {
				continue // Cursor's api5 direct rule is deliberate
			}
			if r.Node == proxygroups.OverseasGroupTag {
				t.Fatalf("preset %q rule %q routes via %s — pin a country instead", name, r.Value, proxygroups.OverseasGroupTag)
			}
			if r.Node == "" {
				t.Fatalf("preset %q rule %q has no node: it falls back to Auto, which includes HK/CN", name, r.Value)
			}
			nodes[r.Node] = true
		}
		if len(nodes) != 1 {
			t.Fatalf("preset %q spreads over %d country groups (%v), want exactly 1", name, len(nodes), nodes)
		}
	}
}

// Hosts seen carrying real traffic on a live gateway (200k connections, 6 days).
// Each must be matched by its pack — a suffix rule or a keyword catch-all. The
// four marked "was uncovered" only worked because the operator had hand-written
// keyword rules the shipped packs did not have.
func TestPresets_AIPacksCoverObservedHosts(t *testing.T) {
	observed := map[string][]string{
		"Claude": {
			"api.anthropic.com", "a-api.anthropic.com", "s-cdn.anthropic.com",
			"a-cdn.anthropic.com", "assets-proxy.anthropic.com",
			"claude.ai", "a.claude.ai", "downloads.claude.ai", "assets.claude.ai",
			"claude.com", "platform.claude.com", "status.claude.com",
			"ee021cd9-afdd-4077-840f-9df23204b8a4.frame.claudeusercontent.com", // was uncovered
			"hcaptcha.com", // was uncovered
		},
		"OpenAI": {
			"chatgpt.com", "ab.chatgpt.com", "ws.chatgpt.com", "learn.chatgpt.com",
			"chat.openai.com", "api.openai.com", "auth.openai.com", "cdn.openai.com",
			"files.openai.com", "images.openai.com", "sentinel.openai.com",
			"support.api.openai.com", "cdn.platform.openai.com",
			"auth-cdn.oaistatic.com", "persistent.oaistatic.com", "help-center-cdn.oaistatic.com",
			"sdmntprsouthcentralus.oaiusercontent.com", "sdmntprcentralus.oaiusercontent.com",
		},
		"Cursor": {"cursor.com", "api5.cursor.sh"},
	}
	for pack, hosts := range observed {
		p := presetByName(t, pack)
		for _, h := range hosts {
			if !packMatches(p, h) {
				t.Fatalf("preset %q does not match %q (seen in real traffic)", pack, h)
			}
		}
	}
}

// packMatches reports whether any enabled rule in the pack would match host,
// mirroring sing-box's domain_suffix / domain_keyword / domain semantics.
func packMatches(p *apitypes.PackPreset, host string) bool {
	for _, r := range p.Rules {
		if !r.Enabled {
			continue
		}
		switch r.Match {
		case apitypes.CustomMatchDomainSuffix:
			if host == r.Value || strings.HasSuffix(host, "."+r.Value) || strings.HasSuffix(host, r.Value) {
				return true
			}
		case apitypes.CustomMatchKeyword:
			if strings.Contains(host, r.Value) {
				return true
			}
		case apitypes.CustomMatchDomain:
			if host == r.Value {
				return true
			}
		}
	}
	return false
}
