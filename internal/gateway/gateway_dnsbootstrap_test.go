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

// No applied exits + default DoH→proxy must not leave final on Cloudflare:
// CN direct dials to 1.1.1.1 hang, so subscription fetch (and every other
// hijack-dns lookup) never completes — the chicken-egg that left k8s gateways
// with 0 nodes forever.
func TestHealBootstrapDNS_NoExitsForcesDirectFinal(t *testing.T) {
	dns := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{
			{Tag: "local", Type: "local"},
			{Tag: "doh", Type: "https", Server: "1.1.1.1", Detour: "proxy"},
		},
		Final: "doh",
	}
	merged, err := buildMergedConfig([]byte(baseCfg), nil, whitelist.Rules{},
		blacklist.Rules{}, quarantine.List{}, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{},
		ModeTUN, ruleset.Sets{}, dns, apitypes.InboundAuth{}, apitypes.InboundListen{},
		apitypes.TUNConfig{Stack: "gvisor", StrictRoute: true},
		nil, nil, "proxy", "", "s", "", t.TempDir())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	block := dnsBlock(t, merged)
	final, _ := block["final"].(string)
	if final != directResolverTag {
		t.Fatalf("no-exit TUN final=%q, want %s (CN-reachable bootstrap)", final, directResolverTag)
	}
	found := false
	for _, s := range block["servers"].([]any) {
		m := s.(map[string]any)
		if m["tag"] == directResolverTag {
			found = true
			if m["type"] != "udp" {
				t.Fatalf("dns-direct type=%v, want udp", m["type"])
			}
			if det, _ := m["detour"].(string); det == "proxy" {
				t.Fatal("dns-direct must not detour via proxy")
			}
		}
	}
	if !found {
		t.Fatal("dns-direct server missing after heal")
	}
}

// Once a real exit exists, leave the operator's DoH-via-proxy final alone.
func TestHealBootstrapDNS_WithExitsKeepsProxiedFinal(t *testing.T) {
	dns := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{
			{Tag: "doh", Type: "https", Server: "1.1.1.1", Detour: "proxy"},
		},
		Final: "doh",
	}
	nodes := []apitypes.Node{{
		Tag: "JP-1", Protocol: "trojan",
		Outbound: json.RawMessage(`{"type":"trojan","tag":"JP-1","server":"203.0.113.10","server_port":443,"password":"x"}`),
	}}
	merged, err := buildMergedConfig([]byte(baseCfg), nodes, whitelist.Rules{},
		blacklist.Rules{}, quarantine.List{}, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{AutoCountry: true},
		ModeTUN, ruleset.Sets{}, dns, apitypes.InboundAuth{}, apitypes.InboundListen{},
		apitypes.TUNConfig{Stack: "gvisor"},
		nil, nil, "proxy", "", "s", "", t.TempDir())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	block := dnsBlock(t, merged)
	if final, _ := block["final"].(string); final != "doh" {
		t.Fatalf("with exits final=%q, want doh (operator anti-leak policy)", final)
	}
}
