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
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
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
	merged, err := buildMergedConfig([]byte(baseCfg), nil, wl, bl, dl, ModeManual, sets,
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
	merged, err := buildMergedConfig([]byte(baseCfg), nil, wl, bl, directlist.Rules{}, ModeManual, sets,
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
		merged, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, tc.mode, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{Stack: "gvisor", StrictRoute: true}, nil, nil, "s", t.TempDir())
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
	merged, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, ModeTUN, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, tun, nil, nil, "s", t.TempDir())
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
	merged2, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, ModeTUN, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{Stack: "gvisor", StrictRoute: true}, nil, nil, "s", t.TempDir())
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
	merged, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{Domains: []string{"ok.com"}}, blacklist.Rules{}, directlist.Rules{}, ModeTUN, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{Stack: "gvisor"}, nil, nil, "s", t.TempDir())
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
