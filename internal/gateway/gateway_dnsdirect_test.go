package gateway

import (
	"encoding/json"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// dohViaProxy is the resolver policy that triggers the split: the only server is
// reached THROUGH the exit node, so its answers carry the exit node's geography.
func dohViaProxy() apitypes.DNSConfig {
	return apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{{Tag: "doh", Type: "https", Server: "8.8.8.8", Detour: "proxy"}},
		Final:   "doh",
	}
}

// cnDirectSets mirrors the real-world setup: mainland domains/IPs route direct,
// a couple of blocked services route through the exit.
func cnDirectSets() ruleset.Sets {
	return ruleset.Sets{Sets: []apitypes.RuleSet{
		{Tag: "geosite-cn", Type: "remote", Format: "binary", URL: "https://example.invalid/geosite-cn.srs", Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true},
		{Tag: "geoip-cn", Type: "remote", Format: "binary", URL: "https://example.invalid/geoip-cn.srs", Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true},
		{Tag: "geosite-google", Type: "remote", Format: "binary", URL: "https://example.invalid/geosite-google.srs", Role: apitypes.RuleRolePermitRouteProxy, UpdateInterval: "1d", Enabled: true},
	}}
}

func buildDNS(t *testing.T, mode string, dns apitypes.DNSConfig, dl directlist.Rules, cr customrules.Rules, sets ruleset.Sets, nodes []apitypes.Node) []byte {
	t.Helper()
	merged, err := buildMergedConfig([]byte(baseCfg), nodes, whitelist.Rules{Domains: []string{"example.com"}},
		blacklist.Rules{}, quarantine.List{}, dl, cr, proxygroups.Config{}, mode, sets,
		dns, apitypes.InboundAuth{}, apitypes.TUNConfig{}, nil, nil, "proxy", "", "sekret", t.TempDir())
	if err != nil {
		t.Fatalf("buildMergedConfig: %v", err)
	}
	return merged
}

func dnsServer(dns map[string]any, tag string) map[string]any {
	for _, s := range mapSlice(dns["servers"]) {
		if s["tag"] == tag {
			return s
		}
	}
	return nil
}

// dnsRuleServerFor returns the server tag of the first dns rule matching the
// given matcher key/value — i.e. which resolver actually answers for it.
func dnsRuleServerFor(dns map[string]any, key, want string) string {
	for _, r := range mapSlice(dns["rules"]) {
		vals, _ := r[key].([]any)
		for _, v := range vals {
			if v == want {
				srv, _ := r["server"].(string)
				return srv
			}
		}
	}
	return ""
}

func outboundByTag(t *testing.T, merged []byte, tag string) map[string]any {
	t.Helper()
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, o := range mapSlice(anyOf(t, cfg["outbounds"])) {
		if o["tag"] == tag {
			return o
		}
	}
	return nil
}

func boolPtr(b bool) *bool { return &b }

func anyOf(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// A resolver behind the exit node must not decide direct dials: mainland
// domains have to resolve through a directly-dialed resolver, or every domestic
// destination is dialed at the exit node's CDN edge (the "domestic traffic is
// slow whenever the gateway runs" bug).
func TestDirectRoutedDomainsResolveDirect(t *testing.T) {
	merged := buildDNS(t, ModeTUN, dohViaProxy(), directlist.Rules{Domains: []string{"nas.local.example"}}, customrules.Rules{}, cnDirectSets(), nil)
	parseValidate(t, merged)
	dns := dnsBlock(t, merged)

	srv := dnsServer(dns, directResolverTag)
	if srv == nil {
		t.Fatalf("no %q server installed: %s", directResolverTag, dns)
	}
	if srv["type"] != "udp" || srv["server"] != DefaultDirectResolver {
		t.Fatalf("direct resolver = %v, want udp %s", srv, DefaultDirectResolver)
	}
	if _, detoured := srv["detour"]; detoured {
		t.Fatalf("direct resolver must have no detour (it has to be dialed direct): %v", srv)
	}

	if got := dnsRuleServerFor(dns, "rule_set", "geosite-cn"); got != directResolverTag {
		t.Fatalf("geosite-cn resolves via %q, want %q", got, directResolverTag)
	}
	if got := dnsRuleServerFor(dns, "domain_suffix", "nas.local.example"); got != directResolverTag {
		t.Fatalf("no-proxy domain resolves via %q, want %q", got, directResolverTag)
	}
	// Proxied destinations keep the remote resolver: their answers must come from
	// the exit node's vantage point.
	if got := dnsRuleServerFor(dns, "rule_set", "geosite-google"); got != "doh" {
		t.Fatalf("geosite-google resolves via %q, want doh", got)
	}
	// The hop that actually picks the dialed IP under TUN (sniffed domain,
	// override_destination) is the direct outbound's own resolver.
	if res := outboundByTag(t, merged, "direct")["domain_resolver"]; res != directResolverTag {
		t.Fatalf("direct outbound domain_resolver = %v, want %q", res, directResolverTag)
	}
}

// An ip_cidr-bearing rule set (geoip-cn) must NEVER reach a DNS rule: sing-box
// would switch that rule to resolve-then-verify and query the domestic resolver
// for every domain, including proxied ones — the answer leak that resolving via
// the exit node exists to prevent.
func TestIPRuleSetsExcludedFromDNSRules(t *testing.T) {
	dns := dnsBlock(t, buildDNS(t, ModeTUN, dohViaProxy(), directlist.Rules{}, customrules.Rules{}, cnDirectSets(), nil))
	for _, r := range mapSlice(dns["rules"]) {
		vals, _ := r["rule_set"].([]any)
		for _, v := range vals {
			if v == "geoip-cn" {
				t.Fatalf("geoip-cn leaked into a dns rule: %v", r)
			}
		}
	}
	// ...while the domain half of the same route rule still splits.
	if got := dnsRuleServerFor(dns, "rule_set", "geosite-cn"); got != directResolverTag {
		t.Fatalf("geosite-cn resolves via %q, want %q", got, directResolverTag)
	}
}

// A route rule whose only matcher is an excluded rule set must not emit an
// empty-matcher DNS rule (that would match everything).
func TestIPOnlyRouteRuleEmitsNoDNSRule(t *testing.T) {
	sets := ruleset.Sets{Sets: []apitypes.RuleSet{
		{Tag: "geoip-cn", Type: "remote", Format: "binary", URL: "https://example.invalid/geoip-cn.srs", Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true},
	}}
	merged := buildDNS(t, ModeTUN, dohViaProxy(), directlist.Rules{}, customrules.Rules{}, sets, nil)
	parseValidate(t, merged)
	for _, r := range mapSlice(dnsBlock(t, merged)["rules"]) {
		matchers := 0
		for _, k := range domainMatcherKeys {
			if _, ok := r[k]; ok {
				matchers++
			}
		}
		if matchers == 0 {
			t.Fatalf("emitted a dns rule with no matcher: %v", r)
		}
	}
}

// DNS precedence must mirror route precedence: route-proxy rule sets are matched
// before route-direct ones, so a domain in both resolves remotely.
func TestDNSRuleOrderMirrorsRouteOrder(t *testing.T) {
	dns := dnsBlock(t, buildDNS(t, ModeTUN, dohViaProxy(), directlist.Rules{}, customrules.Rules{}, cnDirectSets(), nil))
	proxyIdx, directIdx := -1, -1
	for i, r := range mapSlice(dns["rules"]) {
		vals, _ := r["rule_set"].([]any)
		for _, v := range vals {
			if v == "geosite-google" && proxyIdx < 0 {
				proxyIdx = i
			}
			if v == "geosite-cn" && directIdx < 0 {
				directIdx = i
			}
		}
	}
	if proxyIdx < 0 || directIdx < 0 {
		t.Fatalf("missing mirrored rules: proxy=%d direct=%d in %v", proxyIdx, directIdx, dns["rules"])
	}
	if proxyIdx > directIdx {
		t.Fatalf("route-proxy dns rule at %d must precede route-direct at %d", proxyIdx, directIdx)
	}
}

// Custom rules are the top of L4, so they lead the mirrored DNS rules too.
func TestCustomRuleEgressDrivesResolver(t *testing.T) {
	cr := customrules.Rules{Rules: []apitypes.CustomRule{
		{ID: "a", Match: "domain_suffix", Value: "intranet.example", Egress: apitypes.CustomEgressDirect, Enabled: true},
		{ID: "b", Match: "domain_suffix", Value: "openai.com", Egress: apitypes.CustomEgressProxy, Permit: boolPtr(true), Enabled: true},
	}}
	dns := dnsBlock(t, buildDNS(t, ModeManual, dohViaProxy(), directlist.Rules{}, cr, cnDirectSets(), nil))
	if got := dnsRuleServerFor(dns, "domain_suffix", "intranet.example"); got != directResolverTag {
		t.Fatalf("direct custom rule resolves via %q, want %q", got, directResolverTag)
	}
	if got := dnsRuleServerFor(dns, "domain_suffix", "openai.com"); got != "doh" {
		t.Fatalf("proxied custom rule resolves via %q, want doh", got)
	}
}

// A node whose server is a hostname must not be resolved through the proxy group
// it is a member of (resolve-through-itself deadlock): its dial is direct, so its
// resolver must be too.
func TestNodeOutboundsResolveDirect(t *testing.T) {
	nodes := []apitypes.Node{{
		Tag: "hostname-node", Server: "isp.example.com",
		Outbound: json.RawMessage(`{"type":"http","tag":"hostname-node","server":"isp.example.com","server_port":10001}`),
	}}
	merged := buildDNS(t, ModeManual, dohViaProxy(), directlist.Rules{}, customrules.Rules{}, cnDirectSets(), nodes)
	parseValidate(t, merged)
	if res := outboundByTag(t, merged, "hostname-node")["domain_resolver"]; res != directResolverTag {
		t.Fatalf("node domain_resolver = %v, want %q", res, directResolverTag)
	}
	// Groups don't dial a destination — they must stay untouched.
	if grp := outboundByTag(t, merged, ProxyGroupTag); grp != nil {
		if _, set := grp["domain_resolver"]; set {
			t.Fatalf("selector must not carry a domain_resolver: %v", grp)
		}
	}
}

// With a directly-dialed resolver there is nothing to split — the config must be
// left exactly as configured (no synthesized server, no mirrored rules).
func TestNoSplitWhenResolverIsAlreadyDirect(t *testing.T) {
	cfg := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{{Tag: "isp", Type: "udp", Server: "223.5.5.5"}},
		Final:   "isp",
	}
	dns := dnsBlock(t, buildDNS(t, ModeManual, cfg, directlist.Rules{}, customrules.Rules{}, cnDirectSets(), nil))
	if dnsServer(dns, directResolverTag) != nil {
		t.Fatalf("split installed even though the resolver is dialed direct: %v", dns)
	}
	if len(mapSlice(dns["rules"])) != 0 {
		t.Fatalf("mirrored rules emitted needlessly: %v", dns["rules"])
	}
}

// The escape hatch has to actually disable the split.
func TestDisableDirectSplit(t *testing.T) {
	cfg := dohViaProxy()
	cfg.DisableDirectSplit = true
	merged := buildDNS(t, ModeTUN, cfg, directlist.Rules{}, customrules.Rules{}, cnDirectSets(), nil)
	dns := dnsBlock(t, merged)
	if dnsServer(dns, directResolverTag) != nil {
		t.Fatalf("split installed despite disable_direct_split: %v", dns)
	}
	if res := outboundByTag(t, merged, "direct")["domain_resolver"]; res != nil {
		t.Fatalf("direct outbound pinned despite disable_direct_split: %v", res)
	}
}

func TestDirectServerOverride(t *testing.T) {
	cfg := dohViaProxy()
	cfg.DirectServer = "119.29.29.29:5353"
	dns := dnsBlock(t, buildDNS(t, ModeTUN, cfg, directlist.Rules{}, customrules.Rules{}, cnDirectSets(), nil))
	srv := dnsServer(dns, directResolverTag)
	if srv == nil || srv["server"] != "119.29.29.29" || srv["server_port"] != float64(5353) {
		t.Fatalf("direct resolver = %v, want 119.29.29.29:5353", srv)
	}
}

// A user-authored rule for the same domain wins: the mirror only fills gaps.
func TestUserDNSRulesKeepPriority(t *testing.T) {
	cfg := dohViaProxy()
	cfg.Servers = append(cfg.Servers, apitypes.DNSServer{Tag: "corp", Type: "udp", Server: "10.0.0.53"})
	cfg.Rules = []apitypes.DNSRule{{DomainSuffix: []string{"corp.example"}, Server: "corp"}}
	dl := directlist.Rules{Domains: []string{"corp.example"}}
	dns := dnsBlock(t, buildDNS(t, ModeManual, cfg, dl, customrules.Rules{}, cnDirectSets(), nil))
	if got := dnsRuleServerFor(dns, "domain_suffix", "corp.example"); got != "corp" {
		t.Fatalf("user rule overridden: corp.example resolves via %q, want corp", got)
	}
}

// Everything-direct posture: unmatched traffic egresses direct, so the default
// resolver must be the direct one too.
func TestCatchAllDirectFlipsDNSFinal(t *testing.T) {
	merged, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{Domains: []string{"example.com"}},
		blacklist.Rules{}, quarantine.List{}, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{}, ModeTUN, cnDirectSets(),
		dohViaProxy(), apitypes.InboundAuth{}, apitypes.TUNConfig{}, nil, nil, "direct", "", "sekret", t.TempDir())
	if err != nil {
		t.Fatalf("buildMergedConfig: %v", err)
	}
	if final := dnsBlock(t, merged)["final"]; final != directResolverTag {
		t.Fatalf("dns final = %v, want %q when the catch-all egresses direct", final, directResolverTag)
	}
}

func TestSplitResolverAddr(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
		wantPort int
		wantErr  bool
	}{
		{"", DefaultDirectResolver, 0, false},
		{"223.5.5.5", "223.5.5.5", 0, false},
		{"223.5.5.5:53", "223.5.5.5", 53, false},
		{"2400:3200::1", "2400:3200::1", 0, false},
		{"[2400:3200::1]:53", "2400:3200::1", 53, false},
		{"dns.alidns.com", "dns.alidns.com", 0, false},
		{"223.5.5.5:0", "", 0, true},
		{"223.5.5.5:abc", "", 0, true},
		{"https://dns.alidns.com/dns-query", "", 0, true},
	}
	for _, c := range cases {
		addr, port, err := splitResolverAddr(c.in)
		if (err != nil) != c.wantErr {
			t.Fatalf("splitResolverAddr(%q) err = %v, wantErr %v", c.in, err, c.wantErr)
		}
		if err != nil {
			continue
		}
		if addr != c.wantAddr || port != c.wantPort {
			t.Fatalf("splitResolverAddr(%q) = %q,%d want %q,%d", c.in, addr, port, c.wantAddr, c.wantPort)
		}
	}
}

// Remote rule sets must fetch through an explicit http_client: sing-box 1.14
// deprecated both `download_detour` and the implicit default HTTP client, and
// 1.16 removes them — a warning today is a failed start then. The client also
// pins the direct resolver, so the .srs fetch resolves like every other direct
// dial instead of through the exit node.
func TestRuleSetsFetchViaExplicitHTTPClient(t *testing.T) {
	merged := buildDNS(t, ModeManual, dohViaProxy(), directlist.Rules{}, customrules.Rules{}, cnDirectSets(), nil)
	parseValidate(t, merged)

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(cfg["route"], &route); err != nil {
		t.Fatal(err)
	}
	var sets []map[string]any
	if err := json.Unmarshal(route["rule_set"], &sets); err != nil {
		t.Fatal(err)
	}
	if len(sets) == 0 {
		t.Fatal("no rule-set descriptors emitted")
	}
	for _, rs := range sets {
		if _, legacy := rs["download_detour"]; legacy {
			t.Fatalf("%v still uses the removed download_detour option", rs["tag"])
		}
		hc, ok := rs["http_client"].(map[string]any)
		if !ok {
			t.Fatalf("%v has no http_client: %v", rs["tag"], rs)
		}
		// An omitted detour *is* "dial directly". Naming the plain direct outbound
		// is rejected outright — "detour to an empty direct outbound makes no
		// sense" — which the deprecated download_detour accepted. This assertion
		// used to require a non-empty detour, so it was holding the broken shape in
		// place: the box would not start and the test was green.
		if d, _ := hc["detour"].(string); d == "direct" {
			t.Fatalf("%v: http_client detours to the plain direct outbound, which the box refuses: %v", rs["tag"], hc)
		}
		// This config resolves through a proxied DoH, so the direct split exists
		// and the fetch must use it rather than the exit node's resolver.
		if hc["domain_resolver"] != directResolverTag {
			t.Fatalf("%v: rule-set fetch resolves via %v, want %q", rs["tag"], hc["domain_resolver"], directResolverTag)
		}
	}
}

// A fresh install resolves through `local` with no detour, so injectDirectDNS
// never synthesizes dns-direct — and nothing may reference it.
//
// This is the shape that shipped broken. The reference was written
// unconditionally by injectRuleSets while the server was created conditionally
// by injectDirectDNS, so every fresh gateway that switched to Split built a
// config sing-box refused: "domain resolver not found: dns-direct", once per
// rule set. The machines it worked on were the ones where somebody had picked a
// proxied resolver in the console.
//
// Remove the fix and this fails twice: once here, once in the invariant.
func TestFreshInstallRuleSetsDoNotReferenceAResolverNobodyCreates(t *testing.T) {
	// The default DNS: one `local` server, no detour, exactly as `install` seeds it.
	fresh := apitypes.DNSConfig{Servers: []apitypes.DNSServer{{Tag: "local", Type: "local"}}}
	merged := buildDNS(t, ModeManual, fresh, directlist.Rules{}, customrules.Rules{}, cnDirectSets(), nil)
	parseValidate(t, merged)

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	// The invariant is the general guard; running it here proves it covers this.
	if err := assertResolverReferences(cfg); err != nil {
		t.Fatalf("the merged config references a resolver nothing declares: %v", err)
	}

	var route map[string]json.RawMessage
	if err := json.Unmarshal(cfg["route"], &route); err != nil {
		t.Fatal(err)
	}
	var sets []map[string]any
	if err := json.Unmarshal(route["rule_set"], &sets); err != nil {
		t.Fatal(err)
	}
	if len(sets) == 0 {
		t.Fatal("no rule-set descriptors emitted — this test needs a remote one to be meaningful")
	}
	for _, rs := range sets {
		hc, _ := rs["http_client"].(map[string]any)
		if res, _ := hc["domain_resolver"].(string); res != "" {
			t.Fatalf("%v pins resolver %q, but a fresh install never creates one", rs["tag"], res)
		}
		if d, _ := hc["detour"].(string); d == "direct" {
			t.Fatalf("%v: http_client detours to the plain direct outbound: %v", rs["tag"], hc)
		}
	}
}
