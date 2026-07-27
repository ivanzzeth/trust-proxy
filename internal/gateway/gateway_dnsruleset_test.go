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

// A DNS rule naming a rule set that no longer exists must not stop the gateway.
//
// dnscfg validates r.Server and c.Final against the declared DNS servers, and
// never validated r.RuleSet against anything — while the *mirror* side of
// injectDirectDNS does filter, through ruleset.DNSSafeTags. So one path was
// careful and the neighbouring one passed the tag straight through, and sing-box
// answers a dangling one with "rule-set not found: X" at Start.
//
// Which is the expensive shape: disabling or deleting a rule set becomes
// impossible while a DNS rule still mentions it, and the error names DNS rather
// than the rule set the operator just touched. Worse, if the pair is already
// inconsistent on disk — a hand edit, an older profile, a restored snapshot —
// `serve` never comes up at all.
//
// Self-heal rather than refuse: drop the reference, keep the rest of the rule if
// it still matches something, and say so in the log. That is what the rest of the
// engine does with a tag that has gone away (an unknown node egress is skipped, an
// unknown Final falls back to proxy).
func TestDNSRuleReferencingAMissingRuleSetIsDropped(t *testing.T) {
	dns := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{{Tag: "local", Type: "local"}},
		Rules: []apitypes.DNSRule{
			{RuleSet: []string{"geosite-cn", "geosite-deleted"}, Server: "local"},
			{RuleSet: []string{"geosite-gone"}, Server: "local"},
			{DomainSuffix: []string{"example.com"}, RuleSet: []string{"geosite-gone"}, Server: "local"},
		},
		Final: "local",
	}
	sets := ruleset.Sets{Sets: []apitypes.RuleSet{{
		Tag: "geosite-cn", Type: "remote", Format: "binary",
		URL:  "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
		Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true,
	}}}

	merged := buildDNS(t, ModeManual, dns, directlist.Rules{}, customrules.Rules{}, sets, nil)
	parseValidate(t, merged)
	// The claim that matters: it starts. A schema check would pass either way — the
	// tag is a valid string, it just names nothing.
	startBox(t, merged)

	rules := dnsRules(t, merged)
	for i, r := range rules {
		for _, tag := range strSlice(r["rule_set"]) {
			if tag != "geosite-cn" {
				t.Errorf("dns.rules[%d] still references %q, which no rule set declares", i, tag)
			}
		}
	}
	// The surviving reference is kept, and so is a rule that still has another
	// matcher — dropping the dangling tag must not throw away the domain_suffix
	// beside it.
	var keptCN, keptSuffix bool
	for _, r := range rules {
		for _, tag := range strSlice(r["rule_set"]) {
			if tag == "geosite-cn" {
				keptCN = true
			}
		}
		for _, d := range strSlice(r["domain_suffix"]) {
			if d == "example.com" {
				keptSuffix = true
			}
		}
	}
	if !keptCN {
		t.Error("the reference to a rule set that does exist was dropped too")
	}
	if !keptSuffix {
		t.Error("a rule lost its domain_suffix along with the dangling rule_set tag")
	}
	// And a rule left with no matcher at all is removed rather than emitted empty:
	// sing-box rejects a rule that matches nothing.
	for i, r := range rules {
		if len(strSlice(r["rule_set"])) == 0 && len(strSlice(r["domain_suffix"])) == 0 {
			t.Errorf("dns.rules[%d] has no matcher left and should have been removed: %v", i, r)
		}
	}
}

// A disabled rule set is not injected either, so a DNS rule pointing at one is
// just as dangling as a deleted one.
func TestDNSRuleReferencingADisabledRuleSetIsDropped(t *testing.T) {
	dns := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{{Tag: "local", Type: "local"}},
		Rules:   []apitypes.DNSRule{{RuleSet: []string{"geosite-cn"}, Server: "local"}},
		Final:   "local",
	}
	sets := ruleset.Sets{Sets: []apitypes.RuleSet{{
		Tag: "geosite-cn", Type: "remote", Format: "binary",
		URL:  "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
		Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: false,
	}}}

	merged := buildDNS(t, ModeManual, dns, directlist.Rules{}, customrules.Rules{}, sets, nil)
	parseValidate(t, merged)
	startBox(t, merged)

	for i, r := range dnsRules(t, merged) {
		if len(strSlice(r["rule_set"])) > 0 {
			t.Errorf("dns.rules[%d] references a disabled rule set: %v", i, r)
		}
	}
}

// The backstop. Any injector that emits a rule_set reference has to name one that
// exists, and this is the same class of bug as the dangling DNS-server reference
// the resolver invariant was written for — one namespace over.
func TestInvariantRejectsADanglingRuleSetReference(t *testing.T) {
	const base = `{
	  "dns": {"servers":[{"tag":"local","type":"local"}],"final":"local",
	          "rules":[{"rule_set":["nobody-declares-this"],"server":"local"}]},
	  "outbounds": [{"type":"direct","tag":"direct"},{"type":"block","tag":"blocked"}],
	  "route": {"rules": [], "final": "blocked", "rule_set": []}
	}`
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &cfg); err != nil {
		t.Fatal(err)
	}
	err := assertRuleSetReferences(cfg)
	if err == nil {
		t.Fatal("a dangling rule_set reference was accepted; sing-box would refuse to start on it")
	}
	if !strings.Contains(err.Error(), "nobody-declares-this") {
		t.Fatalf("the error does not name the offending tag: %v", err)
	}
}

func TestInvariantAcceptsADeclaredRuleSetReference(t *testing.T) {
	const base = `{
	  "dns": {"servers":[{"tag":"local","type":"local"}],"final":"local",
	          "rules":[{"rule_set":["geosite-cn"],"server":"local"}]},
	  "outbounds": [{"type":"direct","tag":"direct"},{"type":"block","tag":"blocked"}],
	  "route": {"rules": [{"rule_set":["geosite-cn"],"action":"route","outbound":"direct"}],
	            "final": "blocked",
	            "rule_set": [{"tag":"geosite-cn","type":"local","format":"binary","path":"/x.srs"}]}
	}`
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &cfg); err != nil {
		t.Fatal(err)
	}
	if err := assertRuleSetReferences(cfg); err != nil {
		t.Fatalf("a declared reference was rejected: %v", err)
	}
}

// dnsRules pulls dns.rules out of a merged config.
func dnsRules(t *testing.T, merged []byte) []map[string]any {
	t.Helper()
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	raw, ok := cfg["dns"]
	if !ok {
		t.Fatal("no dns block emitted — this test would prove nothing")
	}
	var dns map[string]json.RawMessage
	if err := json.Unmarshal(raw, &dns); err != nil {
		t.Fatal(err)
	}
	var rules []map[string]any
	if r, ok := dns["rules"]; ok {
		if err := json.Unmarshal(r, &rules); err != nil {
			t.Fatal(err)
		}
	}
	return rules
}
