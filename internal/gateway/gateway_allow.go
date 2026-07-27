// injectAllow builds the L3 Permit gate and L4 Route egress (see its own
// doc comment for the exact allow-set/route formula) plus small L3/L4 helpers.
package gateway

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/finalroute"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// injectAllow builds the Permit gate (L3) and the Route egress (L4), then flips
// the catch-all default egress. Permit and Route are orthogonal:
//
//	allow-set (L3) = whitelist domains+ips ∪ role=permit(+route) rule_sets ∪
//	                 custom/pack rules with Permit ∪ private CIDRs (when gate open)
//	direct (L4)    = route-direct rule_sets + no-proxy domains+ips + private CIDRs
//	proxy  (L4)    = route-proxy rule_sets
//	catch-all      = Final when gate present OR posture=Split; else blocked
//
// Route-only sources (no-proxy, route-direct/proxy without permit, custom with
// Permit=false) NEVER join the allow-set. When the allow-set is empty under
// Strict, NO gate is emitted and the catch-all stays blocked (fail-closed).
// Split skips the L3 gate (default-allow) and always flips catch-all to Final.
//
// Custom routing rules (cr) are the ordered, top-priority slice of L4. A node
// egress whose target tag isn't live is skipped (self-heal).
func injectAllow(cfg map[string]json.RawMessage, wl whitelist.Rules, sets ruleset.Sets, dl directlist.Rules, cr customrules.Rules, memberTags []string, final, posture string) error {
	routeRaw, ok := cfg["route"]
	if !ok {
		return nil
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(routeRaw, &route); err != nil {
		return err
	}

	var directSetTags, proxySetTags, permitSetTags []string
	for _, rs := range sets.Sets {
		if !rs.Enabled || rs.Tag == "" {
			continue
		}
		if apitypes.RuleRoleGrantsPermit(rs.Role) {
			permitSetTags = append(permitSetTags, rs.Tag)
		}
		switch apitypes.RuleRoleRouteEgress(rs.Role) {
		case "direct":
			directSetTags = append(directSetTags, rs.Tag)
		case "proxy":
			proxySetTags = append(proxySetTags, rs.Tag)
		}
	}

	wlSfx, wlRgx := splitDomainMatchers(wl.Domains)
	dlSfx, dlRgx := splitDomainMatchers(dl.Domains)

	members := map[string]bool{}
	for _, t := range memberTags {
		members[t] = true
	}
	var customEgress []json.RawMessage
	var customSubRules []map[string]any
	hasCustomPermit := false
	for _, rule := range cr.Rules {
		if !rule.Enabled {
			continue
		}
		apitypes.NormalizeCustomRule(&rule)
		key, ok := customrules.SingboxMatchKey(rule.Match)
		if !ok || rule.Value == "" {
			continue
		}
		eg := rule.RouteEgress()
		if eg == apitypes.CustomEgressNode && !members[rule.Node] {
			continue
		}
		if rule.GrantsPermit() {
			customSubRules = append(customSubRules, map[string]any{key: []string{rule.Value}})
			hasCustomPermit = true
		}
		if eg == "" {
			continue
		}
		var outbound string
		switch eg {
		case apitypes.CustomEgressDirect:
			outbound = "direct"
		case apitypes.CustomEgressProxy:
			outbound = ProxyGroupTag
			if rule.Node != "" && members[rule.Node] {
				outbound = rule.Node
			}
		case apitypes.CustomEgressBlock:
			outbound = "blocked"
		case apitypes.CustomEgressNode:
			outbound = rule.Node
		default:
			continue
		}
		r, _ := json.Marshal(map[string]any{key: []string{rule.Value}, "action": "route", "outbound": outbound})
		customEgress = append(customEgress, r)
	}

	splitOpen := posture == apitypes.PostureSplit
	// Gate ONLY when the user actually permitted something (Strict). Private
	// CIDRs and no-proxy / route-only rule sets must NOT open the gate alone.
	hasUserPermit := len(wlSfx) > 0 || len(wlRgx) > 0 || len(wl.IPs) > 0 ||
		len(permitSetTags) > 0 || hasCustomPermit
	if !hasUserPermit && !splitOpen {
		return nil
	}

	allowSfx := append([]string(nil), wlSfx...)
	allowRgx := append([]string(nil), wlRgx...)
	allowIPs := append(append([]string(nil), wl.IPs...), privateCIDRs...)
	directIPs := append(append([]string(nil), dl.IPs...), privateCIDRs...)

	// L4: custom → no-proxy → route-proxy RS → route-direct RS.
	var egress []json.RawMessage
	egress = append(egress, customEgress...)
	if len(dlSfx) > 0 {
		r, _ := json.Marshal(map[string]any{"domain_suffix": dlSfx, "action": "route", "outbound": "direct"})
		egress = append(egress, r)
	}
	if len(dlRgx) > 0 {
		r, _ := json.Marshal(map[string]any{"domain_regex": dlRgx, "action": "route", "outbound": "direct"})
		egress = append(egress, r)
	}
	if len(directIPs) > 0 {
		r, _ := json.Marshal(map[string]any{"ip_cidr": directIPs, "action": "route", "outbound": "direct"})
		egress = append(egress, r)
	}
	if len(proxySetTags) > 0 {
		r, _ := json.Marshal(map[string]any{"rule_set": proxySetTags, "action": "route", "outbound": ProxyGroupTag})
		egress = append(egress, r)
	}
	if len(directSetTags) > 0 {
		r, _ := json.Marshal(map[string]any{"rule_set": directSetTags, "action": "route", "outbound": "direct"})
		egress = append(egress, r)
	}

	var inserted []json.RawMessage
	if !splitOpen {
		var subRules []map[string]any
		if len(allowSfx) > 0 {
			subRules = append(subRules, map[string]any{"domain_suffix": allowSfx})
		}
		if len(allowRgx) > 0 {
			subRules = append(subRules, map[string]any{"domain_regex": allowRgx})
		}
		if len(allowIPs) > 0 {
			subRules = append(subRules, map[string]any{"ip_cidr": allowIPs})
		}
		if len(permitSetTags) > 0 {
			subRules = append(subRules, map[string]any{"rule_set": permitSetTags})
		}
		// Deliberately NOT here: an exemption for the hosts remote rule sets are
		// fetched from. One was added on the theory that the download passes
		// through this gate, and it does not — sing-box dials the transport named
		// by the descriptor, never consulting route.rules (see injectRuleSets,
		// which is where that problem is actually solved). So the exemption fixed
		// nothing, and what it did do was punch a real hole: the gate has no way to
		// scope a permission to the gateway's own fetch, so it permitted *all*
		// traffic to those hosts, from any process or device, on any port —
		// reachable by anyone who can add a rule set from the Rules page.
		subRules = append(subRules, customSubRules...)
		gate, _ := json.Marshal(map[string]any{
			"type": "logical", "mode": "or", "rules": subRules,
			"invert": true, "action": "route", "outbound": "blocked",
		})
		inserted = append(inserted, gate)
	}
	inserted = append(inserted, egress...)

	var rules []json.RawMessage
	if raw, ok := route["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return err
		}
	}
	catchIdx := catchAllIdx(rules)

	merged := make([]json.RawMessage, 0, len(rules)+len(inserted))
	merged = append(merged, rules[:catchIdx]...)
	merged = append(merged, inserted...)
	merged = append(merged, rules[catchIdx:]...)

	// The catch-all decides where everything unmatched goes — Final in Strict, and
	// the thing that makes default-deny hold at all. It used to be *rewritten* only
	// if the base config already had a rule with a `network` matcher, so a
	// hand-written config without one silently produced a gateway with no catch-all:
	// unmatched traffic then fell through to sing-box's default outbound (the first
	// one in the list, i.e. direct), with no Final and no default-deny, and nothing
	// said so. Measured in a container. Now it is rewritten if present and appended
	// if not.
	newCatchIdx := catchIdx + len(inserted)
	rewritten := false
	if newCatchIdx < len(merged) {
		var catchRule map[string]any
		if err := json.Unmarshal(merged[newCatchIdx], &catchRule); err == nil {
			if _, hasNet := catchRule["network"]; hasNet {
				catchRule["action"] = "route"
				catchRule["outbound"] = resolveFinal(final, memberTags)
				if b, err := json.Marshal(catchRule); err == nil {
					merged[newCatchIdx] = b
					rewritten = true
				}
			}
		}
	}
	if !rewritten {
		catchAll, err := json.Marshal(map[string]any{
			"action": "route", "network": []string{"tcp", "udp"},
			"outbound": resolveFinal(final, memberTags),
		})
		if err != nil {
			return err
		}
		merged = append(merged, catchAll)
	}

	nr, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	route["rules"] = nr
	nrt, err := json.Marshal(route)
	if err != nil {
		return err
	}
	cfg["route"] = nrt
	return nil
}

func sliceHas(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// resolveFinal picks the catch-all outbound (self-heals unknown node tags).
func resolveFinal(outbound string, memberTags []string) string {
	return finalroute.Resolve(outbound, memberTags)
}

// globToRegex converts a whitelist/blacklist glob into a domain_regex pattern:
//
//	*.example.com -> subdomains of example.com
//	foo*          -> prefix match
func globToRegex(g string) string {
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range g {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return b.String()
}

// splitDomainMatchers partitions domain entries into plain suffix matches and
// glob patterns. A plain entry keeps domain_suffix semantics (matches the
// domain + its subdomains); an entry containing * or ? becomes a domain_regex.
// This is how whitelist/blacklist domains gain prefix/suffix/wildcard support
// without a schema change — the match type is encoded in the value itself.
func splitDomainMatchers(domains []string) (suffixes, regexes []string) {
	for _, d := range domains {
		if strings.ContainsAny(d, "*?") {
			regexes = append(regexes, globToRegex(d))
		} else {
			suffixes = append(suffixes, d)
		}
	}
	return
}

func stringOr(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}
