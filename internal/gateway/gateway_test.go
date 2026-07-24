package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

const baseCfg = `{
  "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090", "secret": ""}},
  "inbounds": [{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":17070}],
  "outbounds": [{"type":"direct","tag":"direct"},{"type":"block","tag":"blocked"},{"type":"selector","tag":"proxy","outbounds":["direct"]}],
  "route": {"rules": [{"action":"sniff"},{"network":["tcp","udp"],"action":"route","outbound":"blocked"}], "final":"blocked"}
}`

// build is a thin wrapper around buildMergedConfig with the common test defaults.
func build(t *testing.T, wl whitelist.Rules, bl blacklist.Rules, dl directlist.Rules, sets ruleset.Sets) []byte {
	t.Helper()
	return buildCR(t, wl, bl, dl, customrules.Rules{}, sets, nil)
}

// buildCR adds custom rules + node member tags for the custom-routing tests.
func buildCR(t *testing.T, wl whitelist.Rules, bl blacklist.Rules, dl directlist.Rules, cr customrules.Rules, sets ruleset.Sets, nodes []apitypes.Node) []byte {
	t.Helper()
	merged, err := buildMergedConfig([]byte(baseCfg), nodes, wl, bl, dl, cr, proxygroups.Config{}, ModeManual, sets,
		apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{}, nil, nil, "sekret", t.TempDir())
	if err != nil {
		t.Fatalf("buildMergedConfig: %v", err)
	}
	return merged
}

// parseValidate runs the merged config through sing-box's own option parser to
// prove the emitted route rules (logical + invert + rule_set sub-rules) are
// schema-valid — a JSON-only assertion can't catch a bad rule shape.
func parseValidate(t *testing.T, merged []byte) {
	t.Helper()
	ctx := service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger()))
	ctx = include.Context(ctx)
	if _, err := singjson.UnmarshalExtendedContext[option.Options](ctx, merged); err != nil {
		t.Fatalf("sing-box rejected merged config: %v\n%s", err, merged)
	}
}

func routeRules(t *testing.T, merged []byte) []map[string]any {
	t.Helper()
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(cfg["route"], &route); err != nil {
		t.Fatal(err)
	}
	var rules []map[string]any
	if err := json.Unmarshal(route["rules"], &rules); err != nil {
		t.Fatal(err)
	}
	return rules
}

// --- rule classifiers -------------------------------------------------------

func isSniff(r map[string]any) bool      { return r["action"] == "sniff" }
func isCatchAll(r map[string]any) bool   { return r["network"] != nil }
func isGate(r map[string]any) bool       { return r["type"] == "logical" && r["invert"] == true }
func isGlobalRule(r map[string]any) bool { return r["clash_mode"] == "Global" }
func isInvertReject(r map[string]any) bool {
	return r["action"] == "reject" && r["invert"] == true
}
func isRuleSetReject(r map[string]any) bool {
	return r["action"] == "reject" && r["rule_set"] != nil && r["invert"] != true
}
func isDenyReject(r map[string]any) bool { // blacklist (non-invert, non-ruleset) reject
	return r["action"] == "reject" && r["invert"] != true && r["rule_set"] == nil
}
func hasDestMatcher(r map[string]any) bool {
	return r["domain_suffix"] != nil || r["domain_regex"] != nil || r["ip_cidr"] != nil || r["rule_set"] != nil
}

// isDirectRoute / isProxyRoute identify L4 egress rules: a destination matcher
// routed to direct/proxy. They exclude the management rule (source_port), the
// Global rule (clash_mode), and the network-matcher catch-all.
func isDirectRoute(r map[string]any) bool {
	return r["action"] == "route" && r["outbound"] == "direct" && r["network"] == nil &&
		r["source_port"] == nil && r["clash_mode"] == nil && hasDestMatcher(r)
}
func isProxyRoute(r map[string]any) bool {
	return r["action"] == "route" && r["outbound"] == ProxyGroupTag && r["network"] == nil &&
		r["clash_mode"] == nil && hasDestMatcher(r)
}

func firstIdx(rules []map[string]any, pred func(map[string]any) bool) int {
	for i, r := range rules {
		if pred(r) {
			return i
		}
	}
	return -1
}

func containsStr(v any, want string) bool {
	arr, ok := v.([]any)
	if !ok {
		return false
	}
	for _, x := range arr {
		if s, ok := x.(string); ok && s == want {
			return true
		}
	}
	return false
}

// --- tests ------------------------------------------------------------------

// Invariant 1: no allow inputs => no ACL gate, catch-all stays blocked (deny-all).
func TestACLGate_EmptyDeniesAll(t *testing.T) {
	merged := build(t, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, ruleset.Sets{})
	parseValidate(t, merged)
	rules := routeRules(t, merged)
	if firstIdx(rules, isGate) != -1 {
		t.Fatal("expected NO ACL gate when allow-set is empty")
	}
	ci := firstIdx(rules, isCatchAll)
	if ci == -1 {
		t.Fatal("catch-all missing")
	}
	if rules[ci]["outbound"] != "blocked" {
		t.Fatalf("catch-all must stay blocked (fail-closed), got %v", rules[ci]["outbound"])
	}
}

// Invariant 2 + 5 + full layer order: floor rejects < Global < gate < L4 < catch-all;
// management is top. Whitelist domain is allowed but never picks an egress.
func TestLayerOrder(t *testing.T) {
	wl := whitelist.Rules{
		Domains:   []string{"example.com"},
		IPs:       []string{"203.0.113.7/32"},
		Processes: []string{"curl", "/usr/bin/ssh"},
	}
	bl := blacklist.Rules{Domains: []string{"evil.com"}}
	sets := ruleset.Sets{Sets: []apitypes.RuleSet{
		{Tag: "ads", Type: "remote", Format: "binary", URL: "https://x/ads.srs", Role: apitypes.RuleRoleBlock, DownloadDetour: "direct", UpdateInterval: "1d", Enabled: true},
		{Tag: "cn", Type: "remote", Format: "binary", URL: "https://x/cn.srs", Role: apitypes.RuleRoleAllowDirect, DownloadDetour: "direct", UpdateInterval: "1d", Enabled: true},
		{Tag: "gg", Type: "remote", Format: "binary", URL: "https://x/gg.srs", Role: apitypes.RuleRoleAllowProxy, DownloadDetour: "direct", UpdateInterval: "1d", Enabled: true},
	}}
	merged, err := buildMergedConfig([]byte(baseCfg), nil, wl, bl, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{}, ModeManual, sets,
		apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{}, nil, []int{22, 9096}, "s", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parseValidate(t, merged)
	rules := routeRules(t, merged)

	sniff := firstIdx(rules, isSniff)
	deny := firstIdx(rules, isDenyReject)
	rsReject := firstIdx(rules, isRuleSetReject)
	invert := firstIdx(rules, isInvertReject)
	global := firstIdx(rules, isGlobalRule)
	gate := firstIdx(rules, isGate)
	direct := firstIdx(rules, isDirectRoute)
	proxy := firstIdx(rules, isProxyRoute)
	catch := firstIdx(rules, isCatchAll)

	for name, idx := range map[string]int{"sniff": sniff, "deny": deny, "rsReject": rsReject, "invert": invert, "global": global, "gate": gate, "direct": direct, "proxy": proxy, "catch": catch} {
		if idx == -1 {
			t.Fatalf("missing rule kind %q in %v", name, rules)
		}
	}
	// Floor (reject) rules all above the Global rule and the gate.
	for _, floor := range []int{deny, rsReject, invert} {
		if !(floor < global && floor < gate) {
			t.Fatalf("floor reject at %d must be above Global(%d) and gate(%d)", floor, global, gate)
		}
	}
	// Global above gate; gate above L4 egress; L4 above catch-all.
	if !(sniff < global && global < gate && gate < direct && gate < proxy && direct < catch && proxy < catch) {
		t.Fatalf("bad layer order: sniff=%d global=%d gate=%d direct=%d proxy=%d catch=%d", sniff, global, gate, direct, proxy, catch)
	}
	// Management source_port allow must be the very top (above sniff? no — after
	// prelude): it sits above every floor reject.
	mgmt := firstIdx(rules, func(r map[string]any) bool { return r["source_port"] != nil })
	if mgmt == -1 || mgmt > deny {
		t.Fatalf("management rule at %d not above blacklist(%d)", mgmt, deny)
	}
	// Catch-all flipped to proxy (gate present) and keeps its network matcher.
	if rules[catch]["outbound"] != ProxyGroupTag || rules[catch]["network"] == nil {
		t.Fatalf("catch-all should route->proxy with network matcher, got %v", rules[catch])
	}
}

// Invariant 8 + no-proxy: no-proxy entries + built-in private CIDRs land in the
// gate allow-set AND in an L4 direct rule.
func TestNoProxyDirect(t *testing.T) {
	dl := directlist.Rules{Domains: []string{"intra.corp"}, IPs: []string{"203.0.113.0/24"}}
	// A whitelist domain guarantees a gate even without rule sets.
	wl := whitelist.Rules{Domains: []string{"example.com"}}
	merged := build(t, wl, blacklist.Rules{}, dl, ruleset.Sets{})
	parseValidate(t, merged)
	rules := routeRules(t, merged)

	// Gate must contain an ip_cidr sub-rule with the no-proxy IP and a private CIDR.
	gate := rules[firstIdx(rules, isGate)]
	subs, _ := gate["rules"].([]any)
	var gateIPs any
	for _, s := range subs {
		m := s.(map[string]any)
		if m["ip_cidr"] != nil {
			gateIPs = m["ip_cidr"]
		}
	}
	if !containsStr(gateIPs, "203.0.113.0/24") || !containsStr(gateIPs, "10.0.0.0/8") {
		t.Fatalf("gate ip_cidr must include no-proxy IP + private CIDR, got %v", gateIPs)
	}

	// An L4 direct ip_cidr rule with the no-proxy IP + private CIDR.
	var directIPRule map[string]any
	var directDomRule map[string]any
	for _, r := range rules {
		if isDirectRoute(r) && r["ip_cidr"] != nil {
			directIPRule = r
		}
		if isDirectRoute(r) && r["domain_suffix"] != nil {
			directDomRule = r
		}
	}
	if directIPRule == nil || !containsStr(directIPRule["ip_cidr"], "203.0.113.0/24") || !containsStr(directIPRule["ip_cidr"], "192.168.0.0/16") {
		t.Fatalf("expected L4 direct ip_cidr rule with no-proxy IP + private CIDR, got %v", directIPRule)
	}
	if directDomRule == nil || !containsStr(directDomRule["domain_suffix"], "intra.corp") {
		t.Fatalf("expected L4 direct domain rule with no-proxy domain, got %v", directDomRule)
	}
}

// Invariant 2: a whitelisted domain is allowed but produces NO egress rule of
// its own (egress is decided by L4 / the catch-all, never hardcoded to proxy).
func TestWhitelistNoEgress(t *testing.T) {
	wl := whitelist.Rules{Domains: []string{"example.com"}}
	merged := build(t, wl, blacklist.Rules{}, directlist.Rules{}, ruleset.Sets{})
	parseValidate(t, merged)
	rules := routeRules(t, merged)

	// The gate allow-set must include the whitelist domain.
	gate := rules[firstIdx(rules, isGate)]
	subs, _ := gate["rules"].([]any)
	found := false
	for _, s := range subs {
		if containsStr(s.(map[string]any)["domain_suffix"], "example.com") {
			found = true
		}
	}
	if !found {
		t.Fatalf("whitelist domain missing from gate allow-set: %v", gate)
	}
	// No L4 proxy-egress rule and no direct domain rule for the whitelist domain:
	// the only proxy outbound is the (network-matcher) catch-all.
	for _, r := range rules {
		if isProxyRoute(r) {
			t.Fatalf("whitelist must not emit a proxy-egress rule, found %v", r)
		}
		if isDirectRoute(r) && containsStr(r["domain_suffix"], "example.com") {
			t.Fatalf("whitelist domain must not get an egress rule, found %v", r)
		}
	}
}

// Invariant 5: a domain that is both whitelisted and blacklisted is rejected —
// the blacklist reject sits above the gate/allow.
func TestBlacklistStillFloor(t *testing.T) {
	wl := whitelist.Rules{Domains: []string{"evil.com", "ok.com"}}
	bl := blacklist.Rules{Domains: []string{"evil.com"}, IPs: []string{"6.6.6.6/32"}, Keywords: []string{"track"}}
	merged := build(t, wl, bl, directlist.Rules{}, ruleset.Sets{})
	parseValidate(t, merged)
	rules := routeRules(t, merged)
	deny := firstIdx(rules, isDenyReject)
	gate := firstIdx(rules, isGate)
	catch := firstIdx(rules, isCatchAll)
	if deny == -1 || gate == -1 {
		t.Fatalf("expected blacklist reject + gate, got deny=%d gate=%d", deny, gate)
	}
	if !(deny < gate && gate < catch) {
		t.Fatalf("blacklist(%d) must be above gate(%d) above catch(%d)", deny, gate, catch)
	}
}

// A rule-set-only allow-set (no whitelist) still generates the gate and flips
// the catch-all to proxy.
func TestRuleSetOnlyGeneratesGate(t *testing.T) {
	sets := ruleset.Sets{Sets: []apitypes.RuleSet{
		{Tag: "cn", Type: "remote", Format: "binary", URL: "https://x/cn.srs", Role: apitypes.RuleRoleAllowDirect, DownloadDetour: "direct", UpdateInterval: "1d", Enabled: true},
	}}
	merged := build(t, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, sets)
	parseValidate(t, merged)
	rules := routeRules(t, merged)
	if firstIdx(rules, isGate) == -1 {
		t.Fatal("rule-set allow should generate a gate")
	}
	ci := firstIdx(rules, isCatchAll)
	if rules[ci]["outbound"] != ProxyGroupTag {
		t.Fatalf("catch-all should flip to proxy, got %v", rules[ci]["outbound"])
	}
	// cache_file enabled (rule sets present).
	var cfg map[string]json.RawMessage
	_ = json.Unmarshal(merged, &cfg)
	var exp map[string]json.RawMessage
	_ = json.Unmarshal(cfg["experimental"], &exp)
	if _, ok := exp["cache_file"]; !ok {
		t.Fatal("cache_file not enabled with rule sets present")
	}
}

func TestApplyMode_Inbounds(t *testing.T) {
	for _, tc := range []struct {
		mode      string
		wantTypes []string
	}{
		{ModeManual, []string{"mixed"}},
		{ModeSystem, []string{"mixed"}},
		{ModeTUN, []string{"tun", "mixed"}},
	} {
		merged, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{}, tc.mode, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{Stack: "gvisor", StrictRoute: true}, nil, nil, "s", t.TempDir())
		if err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		var cfg map[string]json.RawMessage
		_ = json.Unmarshal(merged, &cfg)
		var ins []map[string]any
		_ = json.Unmarshal(cfg["inbounds"], &ins)
		if len(ins) != len(tc.wantTypes) {
			t.Fatalf("%s: got %d inbounds, want %d", tc.mode, len(ins), len(tc.wantTypes))
		}
		for i, want := range tc.wantTypes {
			if ins[i]["type"] != want {
				t.Fatalf("%s: inbound[%d]=%v want %s", tc.mode, i, ins[i]["type"], want)
			}
		}
		if tc.mode == ModeSystem && ins[0]["set_system_proxy"] != true {
			t.Fatalf("system mode: set_system_proxy not set")
		}
	}
}

func TestApplyMode_TUNOptions(t *testing.T) {
	tun := apitypes.TUNConfig{
		Stack:          "system",
		MTU:            1400,
		StrictRoute:    false,
		ExcludePackage: []string{"com.example.app"},
	}
	merged, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{}, ModeTUN, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, tun, nil, nil, "s", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]json.RawMessage
	_ = json.Unmarshal(merged, &cfg)
	var ins []map[string]any
	_ = json.Unmarshal(cfg["inbounds"], &ins)
	tunIn := ins[0]
	if tunIn["type"] != "tun" {
		t.Fatalf("inbound[0] is not tun: %v", tunIn["type"])
	}
	if tunIn["stack"] != "system" {
		t.Fatalf("stack=%v want system", tunIn["stack"])
	}
	if tunIn["mtu"] != float64(1400) {
		t.Fatalf("mtu=%v want 1400", tunIn["mtu"])
	}
	ep, ok := tunIn["exclude_package"].([]any)
	if !ok || len(ep) != 1 || ep[0] != "com.example.app" {
		t.Fatalf("exclude_package=%v want [com.example.app]", tunIn["exclude_package"])
	}
	merged2, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{}, ModeTUN, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{Stack: "gvisor", StrictRoute: true}, nil, nil, "s", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var cfg2 map[string]json.RawMessage
	_ = json.Unmarshal(merged2, &cfg2)
	var ins2 []map[string]any
	_ = json.Unmarshal(cfg2["inbounds"], &ins2)
	if _, present := ins2[0]["mtu"]; present {
		t.Fatal("mtu should be omitted when 0 (auto)")
	}
}

// TUN mode keeps the hijack-dns prelude rule directly after sniff, above the floor.
func TestTUNHijackPrelude(t *testing.T) {
	merged, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{Domains: []string{"ok.com"}}, blacklist.Rules{}, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{}, ModeTUN, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{Stack: "gvisor"}, nil, nil, "s", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parseValidate(t, merged)
	rules := routeRules(t, merged)
	hijack := firstIdx(rules, func(r map[string]any) bool { return r["action"] == "hijack-dns" })
	gate := firstIdx(rules, isGate)
	if hijack == -1 {
		t.Fatal("TUN mode missing hijack-dns rule")
	}
	if !(hijack < gate) {
		t.Fatalf("hijack-dns(%d) must be in the prelude, above the gate(%d)", hijack, gate)
	}
}

// --- proxy groups -----------------------------------------------------------

func outbounds(t *testing.T, merged []byte) []map[string]any {
	t.Helper()
	var cfg map[string]json.RawMessage
	_ = json.Unmarshal(merged, &cfg)
	var outs []map[string]any
	_ = json.Unmarshal(cfg["outbounds"], &outs)
	return outs
}

func findOut(outs []map[string]any, tag string) map[string]any {
	for _, o := range outs {
		if o["tag"] == tag {
			return o
		}
	}
	return nil
}

func buildGrouped(t *testing.T, nodes []apitypes.Node, pg proxygroups.Config) []byte {
	t.Helper()
	merged, err := buildMergedConfig([]byte(baseCfg), nodes, whitelist.Rules{Domains: []string{"ok.com"}},
		blacklist.Rules{}, directlist.Rules{}, customrules.Rules{}, pg, ModeManual, ruleset.Sets{},
		apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{}, nil, nil, "s", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return merged
}

func TestProxyGroups_AutoCountry(t *testing.T) {
	nodes := []apitypes.Node{node("🇭🇰 HK-01"), node("🇭🇰 HK-02"), node("🇺🇸 US-01"), node("mystery")}
	merged := buildGrouped(t, nodes, proxygroups.Config{AutoCountry: true})
	parseValidate(t, merged)
	outs := outbounds(t, merged)

	// proxy is a selector over the groups, default = Auto.
	proxy := findOut(outs, ProxyGroupTag)
	if proxy == nil || proxy["type"] != "selector" || proxy["default"] != "Auto" {
		t.Fatalf("proxy should be selector default=Auto, got %v", proxy)
	}
	if !containsStr(proxy["outbounds"], "Auto") || !containsStr(proxy["outbounds"], "🇭🇰 HK") || !containsStr(proxy["outbounds"], "🇺🇸 US") {
		t.Fatalf("proxy selector missing group members: %v", proxy["outbounds"])
	}
	// Auto = urltest over all 4 nodes.
	auto := findOut(outs, "Auto")
	if auto == nil || auto["type"] != "urltest" {
		t.Fatalf("Auto group missing/wrong: %v", auto)
	}
	if m, _ := auto["outbounds"].([]any); len(m) != 4 {
		t.Fatalf("Auto should have all 4 nodes, got %v", auto["outbounds"])
	}
	// Country group HK has both HK nodes.
	hk := findOut(outs, "🇭🇰 HK")
	if hk == nil || hk["type"] != "urltest" {
		t.Fatalf("HK group missing: %v", hk)
	}
	if m, _ := hk["outbounds"].([]any); len(m) != 2 {
		t.Fatalf("HK group should have 2 nodes, got %v", hk["outbounds"])
	}
	// mystery (no country) => Other group present since real countries exist.
	if findOut(outs, "Other") == nil {
		t.Fatal("expected an Other group for the uncategorized node")
	}
}

func TestProxyGroups_UserGroupsAndCollision(t *testing.T) {
	// A node literally tagged "HK" must not collide with a country group.
	nodes := []apitypes.Node{node("🇭🇰 HK"), node("🇯🇵 JP-01"), node("🇯🇵 JP-02")}
	pg := proxygroups.Config{
		AutoCountry: true,
		Groups: []proxygroups.Group{
			{Name: "JP-fast", Type: "urltest", Filter: "country", Value: "JP"},
			{Name: "byName", Type: "select", Filter: "regex", Value: "JP-0"},
			{Name: "pinned", Type: "select", Filter: "manual", Nodes: []string{"🇭🇰 HK"}},
		},
	}
	merged := buildGrouped(t, nodes, pg)
	parseValidate(t, merged)
	outs := outbounds(t, merged)

	// Node "HK" kept; the HK country group got a de-collided tag (not "HK").
	if findOut(outs, "🇭🇰 HK") == nil {
		t.Fatal("country group should be tagged by CountryName (🇭🇰 HK), distinct from node HK")
	}
	// user country group JP-fast has both JP nodes.
	if g := findOut(outs, "JP-fast"); g == nil {
		t.Fatal("JP-fast group missing")
	} else if m, _ := g["outbounds"].([]any); len(m) != 2 {
		t.Fatalf("JP-fast should have 2 JP nodes, got %v", g["outbounds"])
	}
	// regex group matches JP-0* (2), selector type.
	if g := findOut(outs, "byName"); g == nil || g["type"] != "selector" {
		t.Fatalf("byName should be a selector, got %v", g)
	}
	// manual group has the one pinned node.
	if g := findOut(outs, "pinned"); g == nil {
		t.Fatal("pinned group missing")
	} else if m, _ := g["outbounds"].([]any); len(m) != 1 {
		t.Fatalf("pinned should have 1 node, got %v", g["outbounds"])
	}
}

func TestProxyGroups_NoNodes(t *testing.T) {
	merged := buildGrouped(t, nil, proxygroups.Config{AutoCountry: true})
	parseValidate(t, merged)
	proxy := findOut(outbounds(t, merged), ProxyGroupTag)
	if proxy == nil || proxy["type"] != "selector" || !containsStr(proxy["outbounds"], "direct") {
		t.Fatalf("no nodes => proxy selector[direct], got %v", proxy)
	}
}

// --- effective-rules provenance (B) ----------------------------------------

// layerOf classifies a generated route rule into the same layer token that
// EffectiveRules emits, by shape.
func layerOf(r map[string]any) string {
	switch {
	case r["action"] == "sniff" || r["action"] == "hijack-dns":
		return "prelude"
	case r["source_port"] != nil:
		return "L0"
	case r["action"] == "reject":
		return "L1" // blacklist / rule-set-block / process+device invert
	case r["clash_mode"] != nil:
		return "L2"
	case r["type"] == "logical":
		return "L3"
	case r["network"] != nil:
		return "catch-all"
	default:
		return "L4" // route to direct/proxy/node with a matcher
	}
}

func collapse(tokens []string) []string {
	var out []string
	for _, tk := range tokens {
		if len(out) == 0 || out[len(out)-1] != tk {
			out = append(out, tk)
		}
	}
	return out
}

// mgrWith builds a Manager seeded with the given policy so EffectiveRules can be
// compared against a freshly built merged config from the same inputs.
func mgrWith(t *testing.T, wl whitelist.Rules, bl blacklist.Rules, dl directlist.Rules, cr customrules.Rules, sets ruleset.Sets, mgmt []int) *Manager {
	t.Helper()
	m := &Manager{}
	m.wl, m.bl, m.dl, m.cr, m.rulesets, m.mode, m.mgmtPorts = wl, bl, dl, cr, sets, ModeManual, mgmt
	return m
}

// EffectiveRules must mirror, layer-for-layer, what buildMergedConfig actually
// injects — this guards the two (independently coded) orderings against drift.
func TestEffectiveRules_MatchesMergedLayers(t *testing.T) {
	cases := []struct {
		name string
		wl   whitelist.Rules
		bl   blacklist.Rules
		dl   directlist.Rules
		cr   customrules.Rules
		sets ruleset.Sets
		mgmt []int
	}{
		{name: "empty"},
		{
			name: "full",
			wl:   whitelist.Rules{Domains: []string{"ok.com"}, Processes: []string{"curl"}},
			bl:   blacklist.Rules{Domains: []string{"evil.com"}, IPs: []string{"6.6.6.6/32"}},
			dl:   directlist.Rules{Domains: []string{"intra.corp"}, IPs: []string{"203.0.113.0/24"}},
			cr:   customrules.Rules{Rules: []apitypes.CustomRule{{Match: "domain_suffix", Value: "x.com", Action: "proxy", Enabled: true}}},
			sets: ruleset.Sets{Sets: []apitypes.RuleSet{
				{Tag: "ads", Type: "remote", Format: "binary", URL: "https://x/ads.srs", Role: apitypes.RuleRoleBlock, DownloadDetour: "direct", UpdateInterval: "1d", Enabled: true},
				{Tag: "cn", Type: "remote", Format: "binary", URL: "https://x/cn.srs", Role: apitypes.RuleRoleAllowDirect, DownloadDetour: "direct", UpdateInterval: "1d", Enabled: true},
				{Tag: "gg", Type: "remote", Format: "binary", URL: "https://x/gg.srs", Role: apitypes.RuleRoleAllowProxy, DownloadDetour: "direct", UpdateInterval: "1d", Enabled: true},
			}},
			mgmt: []int{22, 9096},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := buildMergedConfig([]byte(baseCfg), nil, tc.wl, tc.bl, tc.dl, tc.cr, proxygroups.Config{}, ModeManual, tc.sets,
				apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{}, nil, tc.mgmt, "s", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			parseValidate(t, merged)
			var realTokens []string
			for _, r := range routeRules(t, merged) {
				realTokens = append(realTokens, layerOf(r))
			}

			m := mgrWith(t, tc.wl, tc.bl, tc.dl, tc.cr, tc.sets, tc.mgmt)
			var viewTokens []string
			for _, v := range m.EffectiveRules() {
				viewTokens = append(viewTokens, v.Layer)
			}

			gotR, gotV := collapse(realTokens), collapse(viewTokens)
			if len(gotR) != len(gotV) {
				t.Fatalf("layer sequence drift:\n merged=%v\n view  =%v", gotR, gotV)
			}
			for i := range gotR {
				if gotR[i] != gotV[i] {
					t.Fatalf("layer[%d] drift: merged=%q view=%q\n merged=%v\n view=%v", i, gotR[i], gotV[i], gotR, gotV)
				}
			}
		})
	}
}

// A dead custom node target is annotated (and its rule inert) in the view.
func TestEffectiveRules_NodeNoteAndEmptyDeny(t *testing.T) {
	// empty policy => only prelude + Global(L2) + catch-all(blocked), no gate.
	m := mgrWith(t, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, customrules.Rules{}, ruleset.Sets{}, nil)
	views := m.EffectiveRules()
	last := views[len(views)-1]
	if last.Layer != "catch-all" || last.Action != "route:blocked" {
		t.Fatalf("empty policy should end in default-deny, got %+v", last)
	}
	for _, v := range views {
		if v.Layer == "L3" {
			t.Fatal("empty policy must not have an ACL gate")
		}
	}

	// A valid allow (whitelist) opens the gate; a dead-node custom rule is noted.
	m2 := mgrWith(t, whitelist.Rules{Domains: []string{"ok.com"}}, blacklist.Rules{}, directlist.Rules{},
		customrules.Rules{Rules: []apitypes.CustomRule{{Match: "domain", Value: "g.com", Action: "node", Node: "GHOST", Enabled: true}}},
		ruleset.Sets{}, nil)
	foundNote := false
	for _, v := range m2.EffectiveRules() {
		if v.Source == "custom" && v.Note != "" {
			foundNote = true
		}
	}
	if !foundNote {
		t.Fatal("dead-node custom rule should carry a 'missing' note")
	}
}

// --- custom routing rules (Task C) -----------------------------------------

func node(tag string) apitypes.Node {
	ob, _ := json.Marshal(map[string]any{"type": "socks", "tag": tag, "server": "1.1.1.1", "server_port": 1080})
	return apitypes.Node{Tag: tag, Protocol: "socks", Server: "1.1.1.1", Port: 1080, Outbound: ob}
}

// A custom direct/proxy/block rule: direct/proxy join the allow-set (they imply
// allow); block does not. Custom rules sit above rule-set egress in L4.
func TestCustomRules_AllowSetAndOrder(t *testing.T) {
	cr := customrules.Rules{Rules: []apitypes.CustomRule{
		{Match: "domain_suffix", Value: "force-proxy.com", Action: "proxy", Enabled: true},
		{Match: "domain_suffix", Value: "go-direct.com", Action: "direct", Enabled: true},
		{Match: "domain_suffix", Value: "blocked-anyway.com", Action: "block", Enabled: true},
	}}
	sets := ruleset.Sets{Sets: []apitypes.RuleSet{
		{Tag: "cn", Type: "remote", Format: "binary", URL: "https://x/cn.srs", Role: apitypes.RuleRoleAllowDirect, DownloadDetour: "direct", UpdateInterval: "1d", Enabled: true},
	}}
	merged := buildCR(t, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, cr, sets, nil)
	parseValidate(t, merged)
	rules := routeRules(t, merged)

	// Gate allow-set contains the direct + proxy custom domains, NOT the block one.
	gate := rules[firstIdx(rules, isGate)]
	subs, _ := gate["rules"].([]any)
	inAllow := func(dom string) bool {
		for _, s := range subs {
			if containsStr(s.(map[string]any)["domain_suffix"], dom) {
				return true
			}
		}
		return false
	}
	if !inAllow("force-proxy.com") || !inAllow("go-direct.com") {
		t.Fatalf("direct/proxy custom rules must join allow-set: %v", gate)
	}
	if inAllow("blocked-anyway.com") {
		t.Fatal("a block custom rule must NOT join the allow-set")
	}

	// Custom rules emit L4 rules above the rule-set direct egress.
	customIdx := firstIdx(rules, func(r map[string]any) bool {
		return containsStr(r["domain_suffix"], "go-direct.com") && r["outbound"] == "direct"
	})
	rsDirectIdx := firstIdx(rules, func(r map[string]any) bool { return containsStr(r["rule_set"], "cn") && r["outbound"] == "direct" })
	blockIdx := firstIdx(rules, func(r map[string]any) bool {
		return containsStr(r["domain_suffix"], "blocked-anyway.com") && r["outbound"] == "blocked" && r["network"] == nil
	})
	gateIdx := firstIdx(rules, isGate)
	if customIdx == -1 || rsDirectIdx == -1 || blockIdx == -1 {
		t.Fatalf("missing rules: custom=%d rsDirect=%d block=%d", customIdx, rsDirectIdx, blockIdx)
	}
	if !(gateIdx < customIdx && customIdx < rsDirectIdx) {
		t.Fatalf("custom rules must be below gate(%d) and above rule-set egress(%d), got %d", gateIdx, rsDirectIdx, customIdx)
	}
}

// A node rule routes to that outbound iff the tag is a live member; otherwise
// the whole rule is skipped (self-heal) and the box still builds.
func TestCustomRules_NodeSelfHeal(t *testing.T) {
	// Valid node target: HK is a subscription node, so its outbound tag exists.
	crOK := customrules.Rules{Rules: []apitypes.CustomRule{
		{Match: "domain_suffix", Value: "via-hk.com", Action: "node", Node: "HK", Enabled: true},
	}}
	merged := buildCR(t, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, crOK, ruleset.Sets{}, []apitypes.Node{node("HK")})
	parseValidate(t, merged)
	rules := routeRules(t, merged)
	if firstIdx(rules, func(r map[string]any) bool {
		return containsStr(r["domain_suffix"], "via-hk.com") && r["outbound"] == "HK"
	}) == -1 {
		t.Fatal("expected a route->HK rule for the valid node target")
	}

	// Dead node target: no such outbound => rule skipped entirely, no gate opened
	// by it, config still valid (would otherwise brick the box).
	crDead := customrules.Rules{Rules: []apitypes.CustomRule{
		{Match: "domain_suffix", Value: "via-ghost.com", Action: "node", Node: "GHOST", Enabled: true},
	}}
	merged2 := buildCR(t, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, crDead, ruleset.Sets{}, nil)
	parseValidate(t, merged2)
	rules2 := routeRules(t, merged2)
	if firstIdx(rules2, func(r map[string]any) bool { return containsStr(r["domain_suffix"], "via-ghost.com") }) != -1 {
		t.Fatal("dead-node rule must be skipped entirely")
	}
	// Its matcher must NOT have opened the gate (it was the only allow input).
	if firstIdx(rules2, isGate) != -1 {
		t.Fatal("a skipped dead-node rule must not open the ACL gate")
	}
	ci := firstIdx(rules2, isCatchAll)
	if rules2[ci]["outbound"] != "blocked" {
		t.Fatalf("with only a dead-node rule, catch-all stays blocked, got %v", rules2[ci]["outbound"])
	}
}

// Geofenced Allow packs emit a `proxy` rule whose Node is the shared Overseas
// group. When the exclusion removes a node (there's an HK node to keep out) the
// group is built and the rule routes there — never to the blocked region. When
// there is nothing to exclude, the group isn't built and the rule gracefully
// falls back to the default proxy selector (still allowed, never blocked).
func TestPresets_OverseasGroupRoutesOrFallsBack(t *testing.T) {
	overseas := proxygroups.OverseasGroupTag // "🌏 Overseas"
	cr := customrules.Rules{Rules: []apitypes.CustomRule{
		{Match: "domain_suffix", Value: "claude.ai", Action: "proxy", Node: overseas, Enabled: true},
	}}
	build := func(nodes []apitypes.Node, exclude []string) []byte {
		t.Helper()
		merged, err := buildMergedConfig([]byte(baseCfg), nodes, whitelist.Rules{}, blacklist.Rules{},
			directlist.Rules{}, cr, proxygroups.Config{AutoCountry: true, ExcludeCountries: exclude}, ModeManual,
			ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{}, nil, nil, "s", t.TempDir())
		if err != nil {
			t.Fatalf("buildMergedConfig: %v", err)
		}
		parseValidate(t, merged)
		return merged
	}
	claudeAllowed := func(rules []map[string]any) bool {
		gi := firstIdx(rules, isGate)
		if gi == -1 {
			return false
		}
		subs, _ := rules[gi]["rules"].([]any)
		for _, s := range subs {
			if containsStr(s.(map[string]any)["domain_suffix"], "claude.ai") {
				return true
			}
		}
		return false
	}

	// A) HK + JP nodes, exclude HK → the Overseas group is built (JP only) and
	//    the rule routes to it, and its members must exclude the HK node.
	mergedA := build([]apitypes.Node{node("🇭🇰 HK-01"), node("🇯🇵 JP-01"), node("🇺🇸 US-01")}, []string{"HK"})
	rulesA := routeRules(t, mergedA)
	if firstIdx(rulesA, func(r map[string]any) bool {
		return containsStr(r["domain_suffix"], "claude.ai") && r["outbound"] == overseas
	}) == -1 {
		t.Fatalf("with an excluded HK node present, claude.ai must route to %q", overseas)
	}
	og := findOut(outbounds(t, mergedA), overseas)
	if og == nil || og["type"] != "urltest" {
		t.Fatalf("Overseas group missing/not urltest: %v", og)
	}
	if m, _ := og["outbounds"].([]any); len(m) != 2 { // JP + US, not HK
		t.Fatalf("Overseas group must exclude the HK node, got %v", og["outbounds"])
	}
	if !claudeAllowed(rulesA) {
		t.Fatal("overseas-routed domain must join the ACL allow-set (A)")
	}

	// B) No node to exclude (only JP) → no Overseas group → rule falls back to the
	//    default proxy selector, and the domain is still allowed (not blocked).
	mergedB := build([]apitypes.Node{node("🇯🇵 JP-01")}, []string{"HK"})
	if findOut(outbounds(t, mergedB), overseas) != nil {
		t.Fatal("with nothing to exclude, the Overseas group must not be built")
	}
	rulesB := routeRules(t, mergedB)
	if firstIdx(rulesB, func(r map[string]any) bool {
		return containsStr(r["domain_suffix"], "claude.ai") && r["outbound"] == ProxyGroupTag
	}) == -1 {
		t.Fatalf("without an Overseas group, claude.ai must fall back to the default proxy selector %q", ProxyGroupTag)
	}
	if !claudeAllowed(rulesB) {
		t.Fatal("overseas-routed domain must still be allowed when the group is absent (B)")
	}
}
