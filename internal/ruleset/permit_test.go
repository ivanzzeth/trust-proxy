package ruleset

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func writeSourceRuleSet(t *testing.T, json string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rs.json")
	if err := os.WriteFile(p, []byte(json), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWarmPermitCacheAndMatchesPermit(t *testing.T) {
	path := writeSourceRuleSet(t, `{
		"version": 1,
		"rules": [
			{"domain_suffix": ["permitted-pack.example"]},
			{"ip_cidr": ["203.0.113.0/24"]}
		]
	}`)

	sets := Sets{Sets: []apitypes.RuleSet{
		{Tag: "pack", Type: "local", Format: "source", Path: path, Role: apitypes.RuleRolePermit, Enabled: true},
	}}
	WarmPermitCache(sets, nil)

	if !MatchesPermit("sub.permitted-pack.example", "1.2.3.4:443") {
		t.Fatal("expected domain-suffix match to be trusted")
	}
	if !MatchesPermit("permitted-pack.example", "") {
		t.Fatal("expected exact registrable domain to match its own suffix entry")
	}
	if MatchesPermit("unrelated.example.com", "") {
		t.Fatal("unrelated domain must not be trusted")
	}
	if !MatchesPermit("", "203.0.113.5:443") {
		t.Fatal("expected ip_cidr match to be trusted")
	}
	if MatchesPermit("", "198.51.100.5:443") {
		t.Fatal("unrelated ip must not be trusted")
	}

	// Disabling the set (re-warm) must drop it from the trust index.
	sets.Sets[0].Enabled = false
	WarmPermitCache(sets, nil)
	if MatchesPermit("sub.permitted-pack.example", "1.2.3.4:443") {
		t.Fatal("disabled rule set must not stay trusted after re-warm")
	}

	// A route-only role (no permit) must never grant trust even if enabled.
	sets.Sets[0].Enabled = true
	sets.Sets[0].Role = apitypes.RuleRoleRouteDirect
	WarmPermitCache(sets, nil)
	if MatchesPermit("sub.permitted-pack.example", "1.2.3.4:443") {
		t.Fatal("route-direct role must not grant permit trust")
	}
}
