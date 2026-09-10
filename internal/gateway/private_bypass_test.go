package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
)

// ruleIPCIDRs returns the ip_cidr values of a rule (flattening logical sub-rules).
func ruleIPCIDRs(r map[string]any) []string {
	var out []string
	if raw, ok := r["ip_cidr"]; ok {
		b, _ := json.Marshal(raw)
		var vals []string
		_ = json.Unmarshal(b, &vals)
		out = append(out, vals...)
	}
	if raw, ok := r["rules"]; ok {
		b, _ := json.Marshal(raw)
		var subs []map[string]any
		_ = json.Unmarshal(b, &subs)
		for _, sub := range subs {
			out = append(out, ruleIPCIDRs(sub)...)
		}
	}
	return out
}

func hasCIDR(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

// The switch moves the built-in LAN ranges off the Route axis and must leave the
// Permit gate alone. Taking them out of the gate too would turn "my exit carries
// 10.0.0.0/8" into "LAN is blocked", which is a different and much worse change.
func TestPrivateBypass_OffLeavesTheGateAlone(t *testing.T) {
	wl := whitelist.Rules{Domains: []string{"allow.example"}}
	const lan = "10.0.0.0/8"

	for _, tc := range []struct {
		name      string
		dl        directlist.Rules
		wantRoute bool
	}{
		{"default (absent)", directlist.Rules{}, true},
		{"explicitly on", directlist.Rules{PrivateDirect: boolPtr(true)}, true},
		{"off", directlist.Rules{PrivateDirect: boolPtr(false)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			merged := build(t, wl, blacklist.Rules{}, tc.dl, ruleset.Sets{})
			parseValidate(t, merged)

			var gate, route bool
			for _, r := range routeRules(t, merged) {
				cidrs := ruleIPCIDRs(r)
				if !hasCIDR(cidrs, lan) {
					continue
				}
				// The gate is the inverted logical rule that sends everything
				// NOT permitted to blocked; the Route rule sends its matches to
				// direct.
				if inv, _ := r["invert"].(bool); inv {
					gate = true
					continue
				}
				if out, _ := r["outbound"].(string); out == "direct" {
					route = true
				}
			}
			if !gate {
				t.Fatalf("%s is not in the Permit gate — flipping the Route switch must never block LAN\n%s", lan, merged)
			}
			if route != tc.wantRoute {
				t.Fatalf("%s on the Route axis = %v, want %v\n%s", lan, route, tc.wantRoute, merged)
			}
		})
	}
}

// With the floor off, LAN has no direct rule of its own, so it reaches the
// catch-all like anything else — that is the whole point for an exit that IS the
// far side of those ranges.
func TestPrivateBypass_OffLetsLANReachTheCatchAll(t *testing.T) {
	wl := whitelist.Rules{Domains: []string{"allow.example"}}
	merged := build(t, wl, blacklist.Rules{}, directlist.Rules{PrivateDirect: boolPtr(false)}, ruleset.Sets{})

	rules := routeRules(t, merged)
	last := rules[len(rules)-1]
	if out, _ := last["outbound"].(string); out != "proxy" {
		t.Fatalf("catch-all outbound=%q, want proxy (Final)\n%s", out, merged)
	}
	for _, r := range rules {
		if out, _ := r["outbound"].(string); out != "direct" {
			continue
		}
		if inv, _ := r["invert"].(bool); inv {
			continue
		}
		if hasCIDR(ruleIPCIDRs(r), "192.168.0.0/16") {
			t.Fatalf("LAN still routed direct with the floor off: %s", mustJSON(r))
		}
	}
}

// A user's own no-proxy IPs are unaffected by the switch: it governs the
// built-in ranges only.
func TestPrivateBypass_OffKeepsUserNoProxyIPs(t *testing.T) {
	wl := whitelist.Rules{Domains: []string{"allow.example"}}
	dl := directlist.Rules{IPs: []string{"198.51.100.0/24"}, PrivateDirect: boolPtr(false)}
	merged := build(t, wl, blacklist.Rules{}, dl, ruleset.Sets{})

	found := false
	for _, r := range routeRules(t, merged) {
		if out, _ := r["outbound"].(string); out != "direct" {
			continue
		}
		if inv, _ := r["invert"].(bool); inv {
			continue
		}
		if hasCIDR(ruleIPCIDRs(r), "198.51.100.0/24") {
			found = true
		}
	}
	if !found {
		t.Fatalf("user no-proxy IP lost when the built-in floor was switched off\n%s", merged)
	}
}

func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", " ")
	return strings.TrimSpace(string(b))
}
