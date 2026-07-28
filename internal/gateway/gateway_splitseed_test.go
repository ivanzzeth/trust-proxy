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

// The Split seed, exactly as a real machine reported it failing.
//
// Reported on v0.11.0: `posture set split` failed with five of thirteen rule sets
// at `context deadline exceeded`, while the same URLs answered HTTP 206 in under a
// second from curl on that machine — through both the system resolver and the one
// sing-box would use. So the sources were reachable and the mirror was not the
// issue, which is what made the earlier theory wrong.
//
// What is different inside the box: thirteen remote sets fetched at startup,
// upstream runs them five at a time with FastFail, and they all share one declared
// http_client whose domain_resolver is pinned to dns-direct. This reproduces that
// shape rather than reasoning about it — the whole seeded slot, that machine's DNS
// policy (a proxied DoH with the direct split on), and no exit node.
//
// Needs the network, so it skips in CI's offline containers. It is here to be run
// by hand while chasing this; it is not a regression gate.
func TestSplitSeedStartsWithTheFullCatalog(t *testing.T) {
	if testing.Short() {
		t.Skip("reaches the network")
	}

	var sets ruleset.Sets
	for _, e := range ruleset.Catalog {
		if e.SuggestedRole == "" {
			continue
		}
		sets.Sets = append(sets.Sets, apitypes.RuleSet{
			Tag: e.Tag, Name: e.Name, Type: "remote", Format: e.Format,
			URL: e.URL, Role: e.SuggestedRole, UpdateInterval: "1d", Enabled: true,
		})
	}
	if len(sets.Sets) < 10 {
		t.Skipf("catalog has only %d entries; this reproduction needs the real seed", len(sets.Sets))
	}
	t.Logf("fetching %d remote rule sets", len(sets.Sets))

	// That machine's DNS: a DoH resolver behind the proxy, so injectDirectDNS
	// synthesizes dns-direct (223.5.5.5) and pins it on the rule-set client.
	dns := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{
			{Tag: "local", Type: "local"},
			{Tag: "doh", Type: "https", Server: "1.1.1.1", Detour: "proxy"},
		},
		Final: "doh",
	}

	// With a subscription applied, which is the variable that was missing: `proxy`
	// becomes a urltest group, and the DNS policy's final server sits behind it
	// (detour: proxy). urltest has not probed yet at rule-set fetch time — its
	// CheckOutbounds runs at PostStart, and rule sets fetch during the router's
	// StartStateStart — so the group has no healthy member. A node that does not
	// answer reproduces that without needing a real subscription.
	nodes := []apitypes.Node{{
		Tag: "exit", Protocol: "socks", Server: "127.0.0.1", Port: 1,
		Outbound: json.RawMessage(`{"type":"socks","tag":"exit","server":"127.0.0.1","server_port":1}`),
	}}

	merged, err := buildMergedConfig([]byte(baseCfg), nodes,
		whitelist.Rules{Domains: []string{"example.com"}}, blacklist.Rules{}, quarantine.List{},
		directlist.Rules{}, customrules.Rules{}, proxygroups.Config{}, ModeManual, sets,
		dns, apitypes.InboundAuth{}, apitypes.TUNConfig{}, nil, nil,
		"proxy", apitypes.PostureSplit, "sekret", "", t.TempDir())
	if err != nil {
		t.Fatalf("buildMergedConfig: %v", err)
	}
	parseValidate(t, merged)

	// What the descriptors ended up as, printed because the first thing to know when
	// this fails is whether they are on the mirror or the primary and what resolver
	// they carry.
	for _, rs := range ruleSetDescriptors(t, merged) {
		t.Logf("  %-28v http_client=%-18v url=%v", rs["tag"], rs["http_client"], rs["url"])
	}
	if raw, ok := clientsOf(t, merged); ok {
		t.Logf("  http_clients=%s", raw)
	}

	startBox(t, merged)
}

func clientsOf(t *testing.T, merged []byte) (string, bool) {
	t.Helper()
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(merged, &cfg); err != nil {
		return "", false
	}
	raw, ok := cfg["http_clients"]
	return string(raw), ok
}
