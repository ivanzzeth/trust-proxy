package gateway

import (
	"encoding/json"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Table-driven safety contracts. Adding a new mode/topology footgun means
// adding a row here — not another one-off TestFooBar.
func TestInvariants_Table(t *testing.T) {
	type checkFn func(t *testing.T, merged []byte)

	cases := []struct {
		name  string
		mode  string
		dns   apitypes.DNSConfig
		nodes []apitypes.Node
		check checkFn
	}{
		{
			name: "TUN rewrites local DNS",
			mode: ModeTUN,
			dns:  apitypes.DNSConfig{Servers: []apitypes.DNSServer{{Tag: "local", Type: "local"}}, Final: "local"},
			check: func(t *testing.T, merged []byte) {
				assertNoLocalDNS(t, merged)
			},
		},
		{
			name: "TUN fakeip final becomes real upstream",
			mode: ModeTUN,
			dns:  apitypes.DNSConfig{Servers: []apitypes.DNSServer{{Tag: "fakeip", Type: "fakeip"}}, Final: "fakeip"},
			check: func(t *testing.T, merged []byte) {
				assertNoLocalDNS(t, merged)
				block := dnsBlock(t, merged)
				final, _ := block["final"].(string)
				if final == "fakeip" {
					t.Fatal("final still fakeip")
				}
			},
		},
		{
			name: "manual keeps local DNS",
			mode: ModeManual,
			dns:  apitypes.DNSConfig{Servers: []apitypes.DNSServer{{Tag: "local", Type: "local"}}, Final: "local"},
			check: func(t *testing.T, merged []byte) {
				block := dnsBlock(t, merged)
				for _, s := range block["servers"].([]any) {
					m := s.(map[string]any)
					if m["tag"] == "local" && m["type"] == "local" {
						return
					}
				}
				t.Fatalf("manual must keep type=local: %+v", block)
			},
		},
		{
			name: "TUN has hijack-dns + auto_detect_interface",
			mode: ModeTUN,
			dns:  apitypes.DNSConfig{},
			check: func(t *testing.T, merged []byte) {
				rules := routeRules(t, merged)
				if firstIdx(rules, func(r map[string]any) bool { return r["action"] == "hijack-dns" }) == -1 {
					t.Fatal("hijack-dns missing")
				}
				var cfg map[string]json.RawMessage
				_ = json.Unmarshal(merged, &cfg)
				var route map[string]any
				_ = json.Unmarshal(cfg["route"], &route)
				if route["auto_detect_interface"] != true {
					t.Fatalf("auto_detect_interface=%v", route["auto_detect_interface"])
				}
			},
		},
		{
			name: "Auto excludes loopback when remotes exist",
			mode: ModeManual,
			nodes: []apitypes.Node{
				func() apitypes.Node {
					ob, _ := json.Marshal(map[string]any{"type": "socks", "tag": "Warp", "server": "127.0.0.1", "server_port": 40000})
					return apitypes.Node{Tag: "Warp", Protocol: "socks", Server: "127.0.0.1", Port: 40000, Outbound: ob}
				}(),
				node("🇯🇵 JP-01"),
			},
			check: func(t *testing.T, merged []byte) {
				auto := findOut(outbounds(t, merged), "Auto")
				for _, m := range auto["outbounds"].([]any) {
					if m == "Warp" {
						t.Fatal("Auto still contains Warp")
					}
				}
				if findOut(outbounds(t, merged), "Local") == nil {
					t.Fatal("Local group missing")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := buildMergedConfig([]byte(baseCfg), tc.nodes,
				whitelist.Rules{Domains: []string{"ok.com"}}, blacklist.Rules{}, directlist.Rules{},
				customrules.Rules{}, proxygroups.Config{}, tc.mode, ruleset.Sets{},
				tc.dns, apitypes.InboundAuth{}, apitypes.TUNConfig{Stack: "gvisor", StrictRoute: true},
				nil, nil, "proxy", "s", t.TempDir())
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			tc.check(t, merged)
		})
	}
}
