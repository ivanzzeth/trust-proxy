package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
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
	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Every other test in this package stops at UnmarshalExtendedContext, and every
// bug in the "the gateway builds a config sing-box refuses" family lives past
// it. Three separate releases shipped that failure — a dangling dns-direct
// reference, a detour naming the empty direct outbound, and the one below — with
// sixty green tests in this package the whole time. Schema-valid is not the same
// claim as starts.
//
// startBox is the missing assertion: it runs the real box.New + Start on a
// merged config, with the listeners moved out of the way so it can run in CI
// beside a live gateway.
func startBox(t *testing.T, merged []byte) {
	t.Helper()

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	// An ephemeral inbound and no Clash listener: this test is about whether the
	// box comes up, not about which ports it owns. Binding 21584/21586 would make
	// it fail on the maintainer's own laptop for a reason that is not the bug.
	delete(cfg, "experimental")
	cfg["inbounds"] = json.RawMessage(
		`[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":0}]`)
	rewritten, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger()))
	ctx = include.Context(ctx)
	options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, rewritten)
	if err != nil {
		t.Fatalf("sing-box rejected the merged config: %v\n%s", err, rewritten)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatalf("box.Start: %v", err)
	}
}

// A fresh install with no exit node yet must be able to fetch its own rule sets.
//
// This is the third time this exact scenario has shipped broken, and the reason
// it keeps escaping is that the failure is invisible until Start. The mechanism:
// injectRuleSets emitted `"http_client": {}` whenever there was no exit to route
// the download through. An http_client that unmarshals to the zero value is
// IsEmpty() (option/http.go:54), so RemoteRuleSet.resolveTransport falls through
// to httpClientManager.DefaultTransport() (route/rule/rule_set_remote.go:285),
// whose fallback sets DefaultOutbound: true (box.go:415-420), which dials
// outboundManager.Default() — and Default() is route.final (box.go:223,
// adapter/outbound/manager.go:303), which in our config is "blocked".
//
// So the gateway dialed its own policy downloads into the block outbound:
//
//	outbound/block[blocked]: blocked connection to raw.githubusercontent.com:443
//	error: initialize rule-set[0]: ... operation not permitted
//
// Note what this is NOT: the download never traverses route.rules, so neither
// the L3 Permit gate nor any exemption in it is involved. A previous fix added
// the rule-set source hosts to the gate's allow-list and released it; the bug
// was untouched, because the packet never reached a routing decision. That fix
// was verified against a log line and a green shape test, which is exactly what
// this test exists to stop being sufficient.
//
// The source here is a local HTTP server, so the assertion is hermetic and
// offline: if the fetch is refused with nothing but loopback involved, the
// refusal cannot be the network.
func TestRuleSetFetchesWithNoExitNode(t *testing.T) {
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":3,"rules":[{"domain_suffix":["example.invalid"]}]}`))
	}))
	t.Cleanup(src.Close)

	sets := ruleset.Sets{Sets: []apitypes.RuleSet{{
		Tag: "local-set", Type: "remote", Format: "source",
		URL:  src.URL + "/local.json",
		Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true,
	}}}

	// No nodes: hasExit is false, which is the branch that emitted the empty
	// http_client. This is a fresh install switching to Split before adding a
	// subscription — the first thing a new user does.
	merged := buildCR(t, whitelist.Rules{Domains: []string{"example.com"}},
		blacklist.Rules{}, directlist.Rules{}, customrules.Rules{}, sets, nil)
	startBox(t, merged)
}

// An exit node must not change how rule sets are fetched.
//
// It used to: with any node applied, the download was routed through the proxy
// group, on the reasoning that this crosses the GFW. But a rule set that cannot
// be fetched on *initial* load is fatal, so that made the gateway's ability to
// start depend on a node being alive — apply a subscription whose nodes are all
// dead on a machine with no rule-set cache yet and nothing comes up, with the
// reason in a log file. The exit here is a closed port, i.e. exactly that case.
func TestRuleSetFetchesWithAnExitNode(t *testing.T) {
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":3,"rules":[{"domain_suffix":["example.invalid"]}]}`))
	}))
	t.Cleanup(src.Close)

	sets := ruleset.Sets{Sets: []apitypes.RuleSet{{
		Tag: "local-set", Type: "remote", Format: "source",
		URL:  src.URL + "/local.json",
		Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true,
	}}}
	merged, err := buildMergedConfig([]byte(baseCfg),
		[]apitypes.Node{{Tag: "exit", Protocol: "socks", Server: "127.0.0.1", Port: 1, Outbound: json.RawMessage(
			`{"type":"socks","tag":"exit","server":"127.0.0.1","server_port":1}`)}},
		whitelist.Rules{Domains: []string{"example.com"}}, blacklist.Rules{}, quarantine.List{},
		directlist.Rules{}, customrules.Rules{}, proxygroups.Config{}, ModeManual, sets,
		apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.InboundListen{}, apitypes.TUNConfig{}, nil, nil,
		"proxy", "", "sekret", "", t.TempDir())
	if err != nil {
		t.Fatalf("buildMergedConfig: %v", err)
	}
	startBox(t, merged)
}

// An empty http_client object is never a correct thing to emit, whatever the
// detour situation, because "empty" is a load-bearing value upstream: it means
// "use the default outbound", and our default outbound is the one that blocks.
//
// This is the fast guard. It fails in milliseconds and names the reason, so the
// next person to touch injectRuleSets does not have to rediscover the chain
// through four files of sing-box internals.
func TestRuleSetHTTPClientIsNeverTheEmptyObject(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nodes []apitypes.Node
	}{
		{"no exit node", nil},
		{"with an exit node", []apitypes.Node{{Tag: "exit", Protocol: "socks", Server: "127.0.0.1", Port: 1, Outbound: json.RawMessage(
			`{"type":"socks","tag":"exit","server":"127.0.0.1","server_port":1}`)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sets := ruleset.Sets{Sets: []apitypes.RuleSet{{
				Tag: "geosite-cn", Type: "remote", Format: "binary",
				URL:  "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
				Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true,
			}}}
			merged := buildCR(t, whitelist.Rules{Domains: []string{"example.com"}},
				blacklist.Rules{}, directlist.Rules{}, customrules.Rules{}, sets, tc.nodes)

			for i, rs := range ruleSetDescriptors(t, merged) {
				hc, present := rs["http_client"]
				if !present {
					t.Fatalf("rule_set[%d] declares no http_client, so it falls back to the "+
						"default outbound, which is route.final = blocked", i)
				}
				if obj, ok := hc.(map[string]any); ok && len(obj) == 0 {
					t.Fatalf("rule_set[%d] http_client is {} — IsEmpty() upstream, which dials "+
						"the default outbound (route.final = blocked) instead of anything routable", i)
				}
			}
		})
	}
}

// The deprecation this shape was migrated to http_client in order to retire.
// An empty http_client still triggers it, so "we handled the 1.16 removal early"
// was not true while the object was empty.
func TestNoImplicitDefaultHTTPClientDeprecation(t *testing.T) {
	sets := ruleset.Sets{Sets: []apitypes.RuleSet{{
		Tag: "geosite-cn", Type: "remote", Format: "binary",
		URL:  "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
		Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true,
	}}}
	merged := buildCR(t, whitelist.Rules{Domains: []string{"example.com"}},
		blacklist.Rules{}, directlist.Rules{}, customrules.Rules{}, sets, nil)

	for i, rs := range ruleSetDescriptors(t, merged) {
		if _, ok := rs["download_detour"]; ok {
			t.Fatalf("rule_set[%d] still uses download_detour (removed in sing-box 1.16)", i)
		}
	}
}

func ruleSetDescriptors(t *testing.T, merged []byte) []map[string]any {
	t.Helper()
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(cfg["route"], &route); err != nil {
		t.Fatal(err)
	}
	var sets []map[string]any
	if raw, ok := route["rule_set"]; ok {
		if err := json.Unmarshal(raw, &sets); err != nil {
			t.Fatal(err)
		}
	}
	if len(sets) == 0 {
		t.Fatal("no rule_set descriptors emitted — this test would prove nothing")
	}
	return sets
}

var _ = time.Second
