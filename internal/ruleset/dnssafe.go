package ruleset

import (
	"strings"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// DNSSafe reports whether rs may be referenced from a sing-box DNS rule.
//
// Only sets that match domains and carry NO ip_cidr items qualify. An
// ip_cidr-bearing set flips a DNS rule into sing-box's resolve-then-verify mode
// (rule_dns.go: WithAddressLimit): the rule's server is queried for EVERY
// domain and the answer is then checked against the IP items. Referencing
// geoip-cn from the direct-resolver rule would therefore send every domain —
// including the proxied ones — to the domestic resolver first, which is exactly
// the answer leak that resolving via the exit node exists to prevent.
//
// Unknown => false. Skipping only costs the client-visible answer for that set;
// the dialed address is still fixed by the direct outbound's pinned
// domain_resolver, which is what decides where the traffic actually goes.
func DNSSafe(rs apitypes.RuleSet) bool {
	if !rs.Enabled || rs.Tag == "" {
		return false
	}
	// Local sets are on disk: decode them (no network) for a definitive answer.
	if rs.Type == "local" && rs.Path != "" {
		entries, err := Decode(rs, nil)
		if err != nil || len(entries) == 0 {
			return false
		}
		for _, e := range entries {
			if e.Kind == "ip_cidr" {
				return false
			}
		}
		return true
	}
	// Remote sets can't be inspected without I/O on the config path, so only the
	// well-known domain-list family (sing-geosite and friends) is accepted.
	return looksLikeDomainList(rs.Tag) || looksLikeDomainList(rs.URL)
}

// looksLikeDomainList matches the sing-geosite naming/URL family and rejects
// anything advertising itself as an IP list.
func looksLikeDomainList(s string) bool {
	v := strings.ToLower(s)
	if v == "" || strings.Contains(v, "geoip") {
		return false
	}
	return strings.Contains(v, "geosite")
}

// DNSSafeTags returns the tags of the enabled sets that may appear in DNS rules.
func DNSSafeTags(sets Sets) map[string]bool {
	out := make(map[string]bool, len(sets.Sets))
	for _, rs := range sets.Sets {
		if DNSSafe(rs) {
			out[rs.Tag] = true
		}
	}
	return out
}
