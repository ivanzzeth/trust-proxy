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

// buildWithBase is build() with a caller-supplied base config, for the rules that
// only matter when the operator has written their own.
func buildWithBase(t *testing.T, base string, wl whitelist.Rules, posture string) []byte {
	t.Helper()
	merged, err := buildMergedConfig([]byte(base), nil, wl, blacklist.Rules{}, quarantine.List{},
		directlist.Rules{}, customrules.Rules{}, proxygroups.Config{}, ModeManual, ruleset.Sets{},
		apitypes.DNSConfig{}, apitypes.InboundAuth{}, apitypes.InboundListen{}, apitypes.TUNConfig{}, nil, nil,
		"proxy", posture, "sekret", "", t.TempDir())
	if err != nil {
		t.Fatalf("buildMergedConfig: %v", err)
	}
	return merged
}

// A hand-written rule that happens to match on `network` must not be mistaken for
// the catch-all and rewritten into its opposite.
//
// catchAllIdx returned the first rule carrying *any* network matcher, and
// injectAllow then rewrote whatever it found into `route → Final`. So the most
// common thing an operator hand-writes — blocking QUIC so TLS stays inspectable —
// turned from "reject all UDP" into "send all UDP to the default egress", silently,
// while the real catch-all below it was left alone. The policy was not partially
// applied; one rule was replaced by its inverse.
//
// The anchor is now the shape of a catch-all rather than the presence of one
// matcher: every network, and nothing else to match on.
func TestAHandWrittenUDPRejectIsNotMistakenForTheCatchAll(t *testing.T) {
	const base = `{
	  "experimental": {"clash_api": {"external_controller": "127.0.0.1:21586", "secret": ""}},
	  "inbounds": [{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":21584}],
	  "outbounds": [{"type":"direct","tag":"direct"},{"type":"block","tag":"blocked"},
	                {"type":"selector","tag":"proxy","outbounds":["direct"]}],
	  "route": {"rules": [
	      {"action":"sniff"},
	      {"network":["udp"],"port":[443],"action":"reject"},
	      {"network":["tcp","udp"],"action":"route","outbound":"blocked"}
	    ], "final":"blocked"}
	}`
	merged := buildWithBase(t, base, whitelist.Rules{Domains: []string{"example.com"}}, "")
	parseValidate(t, merged)
	startBox(t, merged)

	rules := routeRules(t, merged)
	var quicRule map[string]any
	for _, r := range rules {
		nets := strSlice(r["network"])
		if len(nets) == 1 && nets[0] == "udp" {
			quicRule = r
		}
	}
	if quicRule == nil {
		t.Fatal("the hand-written QUIC rule vanished from the config entirely")
	}
	if quicRule["action"] != "reject" {
		t.Fatalf("the operator's QUIC reject was rewritten to %v/%v — that is the inverse of what "+
			"they wrote, and nothing reported it", quicRule["action"], quicRule["outbound"])
	}

	// And the real catch-all still got its rewrite, or default-deny would be off.
	last := rules[len(rules)-1]
	if last["action"] != "route" {
		t.Fatalf("the real catch-all was not rewritten: %v", last)
	}
	nets := strSlice(last["network"])
	if len(nets) != 2 {
		t.Fatalf("the last rule is not the all-networks catch-all: %v", last)
	}
}

// Strict with nothing permitted must still emit a catch-all.
//
// injectAllow returns early when the permit set is empty under Strict, which meant
// a base config with no catch-all of its own got none appended — and the result was
// fail-closed only because route.final happens to be "blocked" in the shipped
// config. Drop that line and unmatched traffic goes to sing-box's default outbound,
// which is the first one in the list: `direct`. A silent fail-open, one edit away,
// in the state a gateway is in before anyone has permitted anything.
func TestStrictWithNothingPermittedStillEmitsACatchAll(t *testing.T) {
	// No `final`, and `direct` first, so the only thing standing between this config
	// and open egress is the catch-all rule itself.
	const base = `{
	  "experimental": {"clash_api": {"external_controller": "127.0.0.1:21586", "secret": ""}},
	  "inbounds": [{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":21584}],
	  "outbounds": [{"type":"direct","tag":"direct"},{"type":"block","tag":"blocked"},
	                {"type":"selector","tag":"proxy","outbounds":["direct"]}],
	  "route": {"rules": [{"action":"sniff"}]}
	}`
	merged := buildWithBase(t, base, whitelist.Rules{}, "")
	parseValidate(t, merged)
	startBox(t, merged)

	rules := routeRules(t, merged)
	last := rules[len(rules)-1]
	if len(strSlice(last["network"])) != 2 {
		t.Fatalf("no catch-all was emitted, so unmatched traffic falls through to the first "+
			"outbound (direct): %v", rules)
	}
	if last["outbound"] != "blocked" {
		t.Fatalf("the catch-all sends unpermitted traffic to %v, want blocked", last["outbound"])
	}
}

// The catch-all's own shape, asserted directly, so the anchor cannot quietly go
// back to matching anything with a `network` key.
func TestIsCatchAllRecognisesOnlyABareAllNetworksRule(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule string
		want bool
	}{
		{"all networks, route", `{"network":["tcp","udp"],"action":"route","outbound":"blocked"}`, true},
		{"all networks, reject", `{"network":["tcp","udp"],"action":"reject"}`, true},
		{"udp only", `{"network":["udp"],"action":"reject"}`, false},
		{"tcp only", `{"network":["tcp"],"action":"route","outbound":"direct"}`, false},
		{"all networks but also a port", `{"network":["tcp","udp"],"port":[443],"action":"reject"}`, false},
		{"all networks but also a domain", `{"network":["tcp","udp"],"domain":["x.example"],"action":"reject"}`, false},
		{"no network at all", `{"domain":["x.example"],"action":"reject"}`, false},
		{"network as a bare string", `{"network":"udp","action":"reject"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCatchAllRule(json.RawMessage(tc.rule)); got != tc.want {
				t.Fatalf("isCatchAllRule(%s) = %v, want %v", tc.rule, got, tc.want)
			}
		})
	}
}
