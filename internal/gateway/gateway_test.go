package gateway

import (
	"encoding/json"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
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

// ruleActions extracts the ordered (action, hasProcessInvert, hasRuleSet) view
// of route.rules from a merged config.
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

func TestInjectOrder_ProcessAboveAllowsAboveCatchAll(t *testing.T) {
	wl := whitelist.Rules{
		Domains:   []string{"example.com"},
		IPs:       []string{"10.0.0.0/8"},
		Processes: []string{"curl", "/usr/bin/ssh"},
	}
	sets := ruleset.Sets{Sets: []apitypes.RuleSet{
		{Tag: "ads", Type: "remote", Format: "binary", URL: "https://x/ads.srs", Role: apitypes.RuleRoleBlock, DownloadDetour: "direct", UpdateInterval: "1d", Enabled: true},
		{Tag: "cn", Type: "remote", Format: "binary", URL: "https://x/cn.srs", Role: apitypes.RuleRoleAllowDirect, DownloadDetour: "direct", UpdateInterval: "1d", Enabled: true},
	}}
	merged, err := buildMergedConfig([]byte(baseCfg), nil, wl, blacklist.Rules{}, ModeManual, sets, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{}, nil, nil, "sekret")
	if err != nil {
		t.Fatal(err)
	}
	rules := routeRules(t, merged)

	// Expected order: sniff, [ads block reject], [process invert reject],
	// [domain allow], [ip allow], [cn allow-direct], catch-all reject.
	idx := map[string]int{}
	for i, r := range rules {
		switch {
		case r["action"] == "sniff":
			idx["sniff"] = i
		case r["action"] == "reject" && r["invert"] == true:
			idx["proc"] = i
		case r["action"] == "reject" && r["rule_set"] != nil:
			idx["block"] = i
		case r["action"] == "route" && r["domain_suffix"] != nil:
			idx["domain"] = i
		case r["action"] == "route" && r["ip_cidr"] != nil:
			idx["ip"] = i
		case r["action"] == "route" && r["rule_set"] != nil:
			idx["allowset"] = i
		case r["action"] == "route" && r["outbound"] == "blocked" && r["network"] != nil:
			idx["catchall"] = i
		}
	}
	for _, k := range []string{"sniff", "proc", "block", "domain", "ip", "allowset", "catchall"} {
		if _, ok := idx[k]; !ok {
			t.Fatalf("missing rule %q in %v", k, rules)
		}
	}
	// Ordering invariants (default-deny must be preserved).
	if !(idx["sniff"] < idx["block"] && idx["block"] < idx["proc"] &&
		idx["proc"] < idx["domain"] && idx["domain"] < idx["catchall"] &&
		idx["allowset"] < idx["catchall"]) {
		t.Fatalf("bad ordering: %v", idx)
	}
	// The catch-all must keep its network matcher (empty matcher = load error).
	if rules[idx["catchall"]]["network"] == nil {
		t.Fatal("catch-all lost its network matcher")
	}

	// clash secret injected + cache_file enabled (rule sets present).
	var cfg map[string]json.RawMessage
	_ = json.Unmarshal(merged, &cfg)
	var exp map[string]json.RawMessage
	_ = json.Unmarshal(cfg["experimental"], &exp)
	if _, ok := exp["cache_file"]; !ok {
		t.Fatal("cache_file not enabled with rule sets present")
	}
}

func TestInjectBlacklist_RejectsAboveWhitelistAllows(t *testing.T) {
	// A domain that is BOTH whitelisted (allow) and blacklisted (reject) must be
	// rejected: the reject rule has to sit above the allow so first-match wins.
	wl := whitelist.Rules{Domains: []string{"evil.com", "example.com"}}
	bl := blacklist.Rules{
		Domains:  []string{"evil.com"},
		Keywords: []string{"tracker"},
		Regexes:  []string{`.*\.onion$`},
		IPs:      []string{"6.6.6.6/32"},
	}
	merged, err := buildMergedConfig([]byte(baseCfg), nil, wl, bl, ModeManual, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{}, nil, nil, "s")
	if err != nil {
		t.Fatal(err)
	}
	rules := routeRules(t, merged)

	idx := map[string]int{}
	for i, r := range rules {
		switch {
		case r["action"] == "sniff":
			idx["sniff"] = i
		case r["action"] == "reject" && r["domain_suffix"] != nil:
			idx["blDomain"] = i
		case r["action"] == "reject" && r["domain_keyword"] != nil:
			idx["blKeyword"] = i
		case r["action"] == "reject" && r["domain_regex"] != nil:
			idx["blRegex"] = i
		case r["action"] == "reject" && r["ip_cidr"] != nil:
			idx["blIP"] = i
		case r["action"] == "route" && r["domain_suffix"] != nil:
			idx["wlAllow"] = i
		case r["action"] == "route" && r["outbound"] == "blocked" && r["network"] != nil:
			idx["catchall"] = i
		}
	}
	for _, k := range []string{"sniff", "blDomain", "blKeyword", "blRegex", "blIP", "wlAllow", "catchall"} {
		if _, ok := idx[k]; !ok {
			t.Fatalf("missing rule %q in %v", k, rules)
		}
	}
	// Every blacklist reject must come after sniff and BEFORE the whitelist allow.
	for _, k := range []string{"blDomain", "blKeyword", "blRegex", "blIP"} {
		if !(idx["sniff"] < idx[k] && idx[k] < idx["wlAllow"]) {
			t.Fatalf("blacklist %q at %d not between sniff(%d) and wlAllow(%d): %v", k, idx[k], idx["sniff"], idx["wlAllow"], idx)
		}
	}
	// Catch-all must stay last and keep its network matcher (default-deny intact).
	if idx["wlAllow"] >= idx["catchall"] || rules[idx["catchall"]]["network"] == nil {
		t.Fatalf("default-deny broken: %v", idx)
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
		merged, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{}, blacklist.Rules{}, tc.mode, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{Stack: "gvisor", StrictRoute: true}, nil, nil, "s")
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
	merged, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{}, blacklist.Rules{}, ModeTUN, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, tun, nil, nil, "s")
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
	if tunIn["strict_route"] != false {
		t.Fatalf("strict_route=%v want false", tunIn["strict_route"])
	}
	ep, ok := tunIn["exclude_package"].([]any)
	if !ok || len(ep) != 1 || ep[0] != "com.example.app" {
		t.Fatalf("exclude_package=%v want [com.example.app]", tunIn["exclude_package"])
	}
	// MTU 0 must omit the "mtu" key entirely (auto).
	merged2, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{}, blacklist.Rules{}, ModeTUN, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.TUNConfig{Stack: "gvisor", StrictRoute: true}, nil, nil, "s")
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
