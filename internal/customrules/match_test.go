package customrules

import (
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestMatchesPermit_CursorPackCoversAgentHost(t *testing.T) {
	var cursor []apitypes.CustomRule
	for _, p := range Presets {
		if p.Name == "Cursor" {
			cursor = p.Rules
			break
		}
	}
	if len(cursor) == 0 {
		t.Fatal("Cursor preset missing")
	}
	rules := Rules{Rules: cursor}
	host := "agentn.global.api5.cursor.sh"
	if !MatchesPermit(rules, host, "1.2.3.4:443") {
		t.Fatalf("Cursor pack must permit %q (domain_suffix cursor.sh)", host)
	}
	if MatchesPermit(rules, "evil.example", "9.9.9.9:443") {
		t.Fatal("unrelated host must not match Cursor pack")
	}
}

func TestMatchesPermit_RouteOnlyDoesNotTrust(t *testing.T) {
	p := false
	rules := Rules{Rules: []apitypes.CustomRule{{
		Match: apitypes.CustomMatchDomainSuffix, Value: "only-route.example",
		Action: apitypes.CustomActionProxy, Egress: apitypes.CustomEgressProxy,
		Permit: &p, Enabled: true,
	}}}
	if MatchesPermit(rules, "x.only-route.example", "1.1.1.1:443") {
		t.Fatal("route-only (Permit=false) must not count as trusted")
	}
}
