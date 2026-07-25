// EffectiveRules: a read-only, human-readable projection of the L0..L4 policy
// layers this package generates, for the console's Rules explain view.
package gateway

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// truncVals returns at most n values, appending a "(+K more)" marker if the
// slice was longer — keeps the explain view readable for big rule-sets.
func truncVals(vals []string, n int) []string {
	if len(vals) <= n {
		return append([]string(nil), vals...)
	}
	out := append([]string(nil), vals[:n]...)
	return append(out, fmt.Sprintf("(+%d more)", len(vals)-n))
}

// EffectiveRules projects the current policy into the ordered, layer-labeled
// view the "why is this allowed/blocked" UI renders. It mirrors, in the SAME
// order, the rules buildMergedConfig injects — but derived directly from the
// stores (the merged config isn't retained). The drift test in gateway_test.go
// asserts the layer sequence here matches a freshly built merged config.
func (m *Manager) EffectiveRules() []apitypes.RuleView {
	m.mu.Lock()
	wl, bl, dl, cr, pg, sets, mode, mgmt, nodes, eps, final, posture :=
		m.wl, m.bl, m.dl, m.cr, m.pg, m.rulesets, m.mode, m.mgmtPorts, m.nodes, m.endpoints, m.final, m.posture
	m.mu.Unlock()
	if posture == "" {
		posture = apitypes.PostureStrict
	}

	var epTags []string
	for _, e := range eps {
		if e.Enabled && e.Tag != "" {
			epTags = append(epTags, e.Tag)
		}
	}
	// Valid custom `node` targets = individual nodes/endpoints ∪ group tags
	// (mirrors injectOutbounds), so a rule pointing at a group isn't flagged stale.
	nodeT := memberTags(nodes, epTags)
	_, groupT := buildProxyGroups(nodeT, loopbackTags(nodes), pg)
	members := map[string]bool{}
	for _, t := range append(append([]string(nil), nodeT...), groupT...) {
		members[t] = true
	}

	var out []apitypes.RuleView
	add := func(v apitypes.RuleView) { out = append(out, v) }

	// prelude: sniff (+ TUN hijack-dns).
	add(apitypes.RuleView{Layer: "prelude", Source: "sniff", Action: "sniff", Note: "detect SNI/domain"})
	if mode == ModeTUN {
		add(apitypes.RuleView{Layer: "prelude", Source: "hijack-dns", Action: "hijack-dns", Matcher: "protocol"})
	}

	// L0 management rescue (topmost).
	if len(mgmt) > 0 {
		vals := make([]string, len(mgmt))
		for i, p := range mgmt {
			vals[i] = strconv.Itoa(p)
		}
		add(apitypes.RuleView{Layer: "L0", Source: "management", Action: "route:direct", Matcher: "source_port", Values: vals, Note: "SSH/API rescue"})
	}

	// L1 security floor.
	if sfx, rgx := splitDomainMatchers(bl.Domains); len(sfx) > 0 || len(rgx) > 0 {
		if len(sfx) > 0 {
			add(apitypes.RuleView{Layer: "L1", Source: "blacklist", Action: "reject", Matcher: "domain_suffix", Values: truncVals(sfx, 20)})
		}
		if len(rgx) > 0 {
			add(apitypes.RuleView{Layer: "L1", Source: "blacklist", Action: "reject", Matcher: "domain_regex", Values: truncVals(rgx, 20)})
		}
	}
	if len(bl.Keywords) > 0 {
		add(apitypes.RuleView{Layer: "L1", Source: "blacklist", Action: "reject", Matcher: "domain_keyword", Values: truncVals(bl.Keywords, 20)})
	}
	if len(bl.Regexes) > 0 {
		add(apitypes.RuleView{Layer: "L1", Source: "blacklist", Action: "reject", Matcher: "domain_regex", Values: truncVals(bl.Regexes, 20)})
	}
	if len(bl.IPs) > 0 {
		add(apitypes.RuleView{Layer: "L1", Source: "blacklist", Action: "reject", Matcher: "ip_cidr", Values: truncVals(bl.IPs, 20)})
	}
	for _, rs := range sets.Sets {
		if rs.Enabled && rs.Tag != "" && apitypes.RuleRoleIsDeny(rs.Role) {
			add(apitypes.RuleView{Layer: "L1", Source: "rule-set:" + rs.Tag, Action: "reject", Matcher: "rule_set", Values: []string{rs.Tag}})
		}
	}
	if len(wl.Processes) > 0 {
		add(apitypes.RuleView{Layer: "L1", Source: "process", Action: "reject", Matcher: "process (inverted)", Values: truncVals(wl.Processes, 20), Note: "unlisted processes can't egress"})
	}
	if len(wl.Devices) > 0 {
		add(apitypes.RuleView{Layer: "L1", Source: "device", Action: "reject", Matcher: "source_ip_cidr (inverted)", Values: truncVals(wl.Devices, 20), Note: "unlisted source devices can't egress"})
	}

	// L2 Global bypass (always injected; inert in Rule mode).
	add(apitypes.RuleView{Layer: "L2", Source: "global", Action: "route:proxy", Matcher: "clash_mode", Values: []string{"Global"}, Note: "only when routing mode = Global"})

	// L3 Permit / L4 Route — orthogonal axes.
	var directSets, proxySets, permitSets []string
	for _, rs := range sets.Sets {
		if !rs.Enabled || rs.Tag == "" {
			continue
		}
		if apitypes.RuleRoleGrantsPermit(rs.Role) {
			permitSets = append(permitSets, rs.Tag)
		}
		switch apitypes.RuleRoleRouteEgress(rs.Role) {
		case "direct":
			directSets = append(directSets, rs.Tag)
		case "proxy":
			proxySets = append(proxySets, rs.Tag)
		}
	}
	wlSfx, wlRgx := splitDomainMatchers(wl.Domains)
	dlSfx, dlRgx := splitDomainMatchers(dl.Domains)

	var permitCustom []apitypes.CustomRule
	var routeCustom []apitypes.CustomRule
	for _, r := range cr.Rules {
		if !r.Enabled {
			continue
		}
		apitypes.NormalizeCustomRule(&r)
		eg := r.RouteEgress()
		deadNode := eg == apitypes.CustomEgressNode && !members[r.Node]
		if r.GrantsPermit() && !deadNode {
			permitCustom = append(permitCustom, r)
		}
		if eg != "" {
			routeCustom = append(routeCustom, r)
		}
	}
	hasUserPermit := len(wlSfx) > 0 || len(wlRgx) > 0 || len(wl.IPs) > 0 ||
		len(permitSets) > 0 || len(permitCustom) > 0
	splitOpen := posture == apitypes.PostureSplit

	if !hasUserPermit && !splitOpen {
		add(apitypes.RuleView{Layer: "catch-all", Source: "default-deny", Action: "route:blocked", Matcher: "network", Note: "nothing permitted → everything blocked (fail-closed)"})
		return out
	}

	if splitOpen {
		add(apitypes.RuleView{Layer: "L3", Source: "posture:split", Action: "gate-open", Matcher: "", Note: "Split posture — Permit gate skipped (default-allow); L1 floor + L4 + Final still apply"})
	} else {
		// L3 Permit gate — list every source.
		var allowBits []string
		if n := len(wlSfx) + len(wlRgx) + len(wl.IPs); n > 0 {
			allowBits = append(allowBits, fmt.Sprintf("whitelist(%d)", n))
		}
		for _, tag := range permitSets {
			allowBits = append(allowBits, "rule-set:"+tag)
		}
		for _, r := range permitCustom {
			src := "custom"
			if r.Pack != "" {
				src = "pack:" + r.Pack
			}
			allowBits = append(allowBits, fmt.Sprintf("%s:%s=%s", src, r.Match, r.Value))
		}
		allowBits = append(allowBits, "private-CIDRs")
		add(apitypes.RuleView{Layer: "L3", Source: "permit-gate", Action: "route:blocked", Matcher: "logical (inverted)", Values: truncVals(allowBits, 40), Note: "anything NOT permitted is blocked; Route never opens this gate"})
	}

	// L4 Route: custom → no-proxy → route-proxy RS → route-direct RS → Final.
	for _, r := range routeCustom {
		key, ok := customrules.SingboxMatchKey(r.Match)
		if !ok || r.Value == "" {
			continue
		}
		src := "custom"
		if r.Pack != "" {
			src = "pack:" + r.Pack
		}
		v := apitypes.RuleView{Layer: "L4", Source: src, Matcher: key, Values: []string{r.Value}}
		if !r.GrantsPermit() {
			v.Note = "route-only (does not permit)"
		}
		switch r.RouteEgress() {
		case apitypes.CustomEgressDirect:
			v.Action = "route:direct"
		case apitypes.CustomEgressProxy:
			if r.Node != "" && members[r.Node] {
				v.Action = "route:" + r.Node
			} else {
				v.Action = "route:proxy"
				if r.Node != "" {
					v.Note = strings.TrimSpace(v.Note + " ; group " + r.Node + " missing — via proxy")
				}
			}
		case apitypes.CustomEgressBlock:
			v.Action = "route:blocked"
		case apitypes.CustomEgressNode:
			v.Action = "route:" + r.Node
			if !members[r.Node] {
				v.Note = "node " + r.Node + " missing — rule skipped"
			}
		}
		add(v)
	}
	if len(dlSfx) > 0 {
		add(apitypes.RuleView{Layer: "L4", Source: "no-proxy", Action: "route:direct", Matcher: "domain_suffix", Values: truncVals(dlSfx, 20), Note: "route-only (does not permit)"})
	}
	if len(dlRgx) > 0 {
		add(apitypes.RuleView{Layer: "L4", Source: "no-proxy", Action: "route:direct", Matcher: "domain_regex", Values: truncVals(dlRgx, 20), Note: "route-only (does not permit)"})
	}
	ipVals := append(append([]string(nil), dl.IPs...), privateCIDRs...)
	add(apitypes.RuleView{Layer: "L4", Source: "no-proxy", Action: "route:direct", Matcher: "ip_cidr", Values: truncVals(ipVals, 20), Note: "includes built-in LAN/private ranges; route-only"})
	for _, tag := range proxySets {
		add(apitypes.RuleView{Layer: "L4", Source: "rule-set:" + tag, Action: "route:proxy", Matcher: "rule_set", Values: []string{tag}})
	}
	for _, tag := range directSets {
		note := ""
		if !sliceHas(permitSets, tag) {
			note = "route-only (does not permit)"
		}
		add(apitypes.RuleView{Layer: "L4", Source: "rule-set:" + tag, Action: "route:direct", Matcher: "rule_set", Values: []string{tag}, Note: note})
	}

	allTags := append(append([]string(nil), nodeT...), groupT...)
	egress := resolveFinal(final, allTags)
	note := "Final — permitted traffic with no explicit egress; never opens an empty gate"
	if splitOpen {
		note = "Final — Split default-allow catch-all egress"
	}
	if egress != final && final != "" {
		note = "Final " + final + " missing — via " + egress
	}
	add(apitypes.RuleView{Layer: "catch-all", Source: "default", Action: "route:" + egress, Matcher: "network", Note: note})
	return out
}
