package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// --clash-addr has to reach the config, not just the API's client.
//
// It configured only the client: the port sing-box actually bound came from
// whatever the config file said. So the flag did half a job silently. Running a
// second instance with --clash-addr pointed at a free port still tried to bind
// the config's port, collided with the running gateway, and exited 1 with the
// reason only in a log file — which is how two debugging sessions on this repo
// were spent in one day, mine and the user's.
//
// The secret was already injected from its flag. Injecting one half of a
// listener's configuration and reading the other half from disk is the kind of
// asymmetry that looks fine until the two disagree.
func TestClashAPIAddressComesFromTheFlag(t *testing.T) {
	const base = `{"experimental":{"clash_api":{"external_controller":"127.0.0.1:21586","secret":"old"}}}`

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &cfg); err != nil {
		t.Fatal(err)
	}
	if err := injectClashSecret(cfg, "s3cret", "127.0.0.1:31586"); err != nil {
		t.Fatal(err)
	}

	ca := clashAPI(t, cfg)
	if got := ca["external_controller"]; got != "127.0.0.1:31586" {
		t.Fatalf("external_controller = %v, want the address the flag asked for", got)
	}
	if got := ca["secret"]; got != "s3cret" {
		t.Fatalf("secret = %v, want the injected one", got)
	}
}

// An empty flag means "leave it alone", so a config with a deliberate address
// keeps it. Overwriting with a default would be a different bug in the same
// family as the one above.
func TestClashAPIKeepsTheConfigWhenTheFlagIsEmpty(t *testing.T) {
	const base = `{"experimental":{"clash_api":{"external_controller":"192.168.1.9:9090","secret":"mine"}}}`

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &cfg); err != nil {
		t.Fatal(err)
	}
	if err := injectClashSecret(cfg, "", ""); err != nil {
		t.Fatal(err)
	}

	ca := clashAPI(t, cfg)
	if got := ca["external_controller"]; got != "192.168.1.9:9090" {
		t.Fatalf("external_controller = %v, want it untouched", got)
	}
	if got := ca["secret"]; got != "mine" {
		t.Fatalf("secret = %v, want it untouched", got)
	}
}

func clashAPI(t *testing.T, cfg map[string]json.RawMessage) map[string]any {
	t.Helper()
	var exp map[string]json.RawMessage
	if err := json.Unmarshal(cfg["experimental"], &exp); err != nil {
		t.Fatal(err)
	}
	var ca map[string]any
	if err := json.Unmarshal(exp["clash_api"], &ca); err != nil {
		t.Fatal(err)
	}
	return ca
}

// The gateway has to be allowed to fetch its own policy inputs.
//
// Remote rule sets are downloaded by sing-box through its *default* outbound,
// which means the download goes through route.rules — straight into our own
// Permit gate. Under default-deny that is a reject, and the log said exactly
// that: "outbound/block[blocked]: blocked connection to
// raw.githubusercontent.com:443", surfaced to the user as six lines of
// "operation not permitted". The gateway was refusing to start because it had
// blocked itself.
//
// The old `download_detour` bypassed route.rules entirely. Its replacement,
// http_client.detour, is rejected when it names an outbound with no dialer
// options ("detour to an empty direct outbound makes no sense") — and whether our
// direct outbound has any depends on whether the DNS split is on, which is not a
// coupling to build on.
//
// So: an explicit exemption for the hosts the enabled rule sets are fetched
// from, below the deny floor and above the gate, where it is visible in
// `rules ls` and auditable.
func TestRuleSetSourcesAreExemptFromTheOwnGate(t *testing.T) {
	sets := ruleset.Sets{Sets: []apitypes.RuleSet{{
		Tag: "geosite-cn", Type: "remote", Format: "binary",
		URL:  "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
		Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true,
	}}}
	merged := buildDNS(t, ModeManual, dohViaProxy(), directlist.Rules{}, customrules.Rules{}, sets, nil)
	parseValidate(t, merged)

	// The assertion is about the outcome, not the mechanism: the gate is the only
	// thing that rejects an unlisted destination, so being inside its allow-list
	// is exactly "this download is not blocked". Where the traffic then goes is
	// L4's business — proxy when an exit exists, direct when it does not.
	gate := findPermitGate(t, routeRules(t, merged))
	if gate == nil {
		t.Fatal("no Permit gate in a strict config — this test would prove nothing")
	}
	if !allowListCovers(gate, "cdn.jsdelivr.net") {
		t.Fatalf("the rule-set source host is not permitted, so the gateway blocks its own download:\n%v", gate)
	}
}

// A rule set the operator disabled is not fetched, so it must not widen the
// allow-list. An exemption that outlives its reason is just a hole.
func TestDisabledRuleSetSourceIsNotPermitted(t *testing.T) {
	sets := ruleset.Sets{Sets: []apitypes.RuleSet{{
		Tag: "geosite-cn", Type: "remote", Format: "binary",
		URL:  "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
		Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: false,
	}}}
	merged := buildDNS(t, ModeManual, dohViaProxy(), directlist.Rules{}, customrules.Rules{}, sets, nil)
	parseValidate(t, merged)

	if gate := findPermitGate(t, routeRules(t, merged)); gate != nil && allowListCovers(gate, "cdn.jsdelivr.net") {
		t.Fatal("a disabled rule set still permitted its source host")
	}
}

// findPermitGate returns the inverted allow-list reject that closes default-deny.
func findPermitGate(t *testing.T, rules []map[string]any) map[string]any {
	t.Helper()
	for _, r := range rules {
		if inv, _ := r["invert"].(bool); inv && r["type"] == "logical" {
			return r
		}
	}
	return nil
}

// allowListCovers reports whether the gate lets host through, by exact domain or
// by suffix.
func allowListCovers(gate map[string]any, host string) bool {
	subs, _ := gate["rules"].([]any)
	for _, sr := range subs {
		m, ok := sr.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"domain", "domain_suffix"} {
			for _, v := range strSlice(m[key]) {
				if v == host || strings.HasSuffix(host, v) {
					return true
				}
			}
		}
	}
	return false
}

func strSlice(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
