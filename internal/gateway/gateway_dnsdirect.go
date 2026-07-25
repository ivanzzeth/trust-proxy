// Split DNS: "DNS follows route". Domains whose traffic egresses `direct` must
// be resolved by a resolver we also reach directly — otherwise a resolver behind
// the exit node answers with its own region's CDN edges and the direct dial goes
// China -> Korea/India/Singapore instead of staying domestic (the "everything
// domestic is slow while the gateway runs" bug).
package gateway

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

const (
	// directResolverTag is the synthesized DNS server that answers for
	// direct-routed domains. Dialed with no detour => it leaves via `direct`.
	directResolverTag = "dns-direct"
	// DefaultDirectResolver is the resolver used for direct-routed domains when
	// the user hasn't picked one: a mainland UDP resolver, which is exactly the
	// point — it returns mainland CDN answers for mainland destinations. GFW
	// poisoning is irrelevant here because only domains we egress DIRECT are
	// looked up through it (a poisoned foreign domain dialed direct is dead
	// either way; those domains route via the proxy and keep the DoH resolver).
	DefaultDirectResolver = "223.5.5.5"
)

// domainMatcherKeys are the route-rule matchers that carry over to a DNS rule.
// ip_cidr/port/process matchers have no meaning for a query and are dropped
// (an IP dial needs no resolution in the first place).
var domainMatcherKeys = []string{"domain", "domain_suffix", "domain_keyword", "domain_regex", "rule_set"}

// dialingOutboundSkip are outbound types that never dial a destination
// themselves (groups) or discard it — no domain_resolver needed.
var dialingOutboundSkip = map[string]bool{
	"selector": true, "urltest": true, "block": true, "blackhole": true, "dns": true,
}

// injectDirectDNS mirrors the final route table into the dns block so every
// domain is resolved by the resolver that matches its egress:
//
//	route: ... -> direct   =>  dns: ... -> dns-direct (dialed direct, domestic)
//	route: ... -> proxy    =>  dns: ... -> the configured (DoH-via-exit) server
//
// It is a no-op unless the resolver that direct dials would otherwise use sits
// behind the proxy (detour="proxy"): with a directly-dialed resolver (e.g. the
// default type=local) answers already match the egress and nothing needs
// splitting. Also pins domain_resolver on every dialing outbound:
//   - `direct`: TUN re-resolves the sniffed domain when it overrides the
//     destination, so this is the hop that actually decides the dialed IP.
//   - nodes: a node whose server is a hostname (isp.decodo.com) would otherwise
//     resolve through DoH-via-proxy — i.e. through itself. Resolving it direct
//     breaks that circle.
//
// Runs last (from applyInvariants) so it mirrors the route table every other
// inject* has finished writing, and is idempotent.
// dnsSafeTags: rule-set tags that may appear in a DNS rule (see ruleset.DNSSafe).
// Tags outside the set are dropped from the mirror instead of dragging every
// lookup through resolve-then-verify.
func injectDirectDNS(cfg map[string]json.RawMessage, d apitypes.DNSConfig, dnsSafeTags map[string]bool) error {
	if d.DisableDirectSplit {
		return nil
	}
	dnsRaw, ok := cfg["dns"]
	if !ok {
		return nil // no dns block => sing-box's own system resolver, already direct
	}
	var dns map[string]any
	if err := json.Unmarshal(dnsRaw, &dns); err != nil {
		return err
	}
	var route map[string]json.RawMessage
	if raw, ok := cfg["route"]; ok {
		if err := json.Unmarshal(raw, &route); err != nil {
			return err
		}
	} else {
		return nil
	}

	servers, _ := dns["servers"].([]any)
	detour := map[string]string{}
	synth := map[string]bool{}
	var firstReal string
	for _, s := range servers {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := m["tag"].(string)
		if tag == "" {
			continue
		}
		det, _ := m["detour"].(string)
		detour[tag] = det
		typ, _ := m["type"].(string)
		if typ == "fakeip" || typ == "hosts" {
			synth[tag] = true
			continue
		}
		if firstReal == "" {
			firstReal = tag
		}
	}

	// remote = the resolver a direct dial would use today. Only a proxy-detoured
	// one is wrong for direct traffic; anything else already matches the egress.
	remote := ""
	_ = json.Unmarshal(route["default_domain_resolver"], &remote)
	if remote == "" || synth[remote] {
		remote, _ = dns["final"].(string)
	}
	if remote == "" || synth[remote] {
		remote = firstReal
	}
	if remote == "" || detour[remote] != "proxy" {
		return nil
	}

	// (1) the direct-dialed resolver itself
	addr, port, err := splitResolverAddr(d.DirectServer)
	if err != nil {
		return err
	}
	existingDetour, exists := detour[directResolverTag]
	if !exists || existingDetour == "proxy" {
		srv := map[string]any{"type": "udp", "tag": directResolverTag, "server": addr}
		if port > 0 {
			srv["server_port"] = port
		}
		if exists {
			// Stale data (an old profile, a hand-edited file) carrying our reserved
			// tag behind the proxy would defeat the whole split: replace it.
			kept := make([]any, 0, len(servers))
			for _, s := range mapSlice(servers) {
				if s["tag"] != directResolverTag {
					kept = append(kept, s)
				}
			}
			servers = kept
		}
		dns["servers"] = append(servers, srv)
	}

	// (2) mirror the route table's domain decisions, in route order, so DNS
	// precedence matches routing precedence (a domain in both a route-proxy and a
	// route-direct rule set resolves the way it is actually routed).
	var rules []json.RawMessage
	if raw, ok := route["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return err
		}
	}
	mirrored := make([]any, 0, len(rules))
	for _, r := range rules {
		var m map[string]any
		if err := json.Unmarshal(r, &m); err != nil {
			continue
		}
		if action, _ := m["action"].(string); action != "" && action != "route" {
			continue // sniff / hijack-dns / reject: no egress to follow
		}
		// The L3 permit gate is a logical/inverted rule routing to `blocked`; a
		// blocked destination needs no address at all.
		if typ, _ := m["type"].(string); typ == "logical" {
			continue
		}
		if inv, _ := m["invert"].(bool); inv {
			continue
		}
		ob, _ := m["outbound"].(string)
		if ob == "" || ob == "blocked" {
			continue
		}
		rule := map[string]any{}
		for _, k := range domainMatcherKeys {
			v, ok := m[k]
			if !ok {
				continue
			}
			if k == "rule_set" {
				v = keepDNSSafeTags(v, dnsSafeTags)
				if v == nil {
					continue
				}
			}
			rule[k] = v
		}
		if len(rule) == 0 {
			continue // IP/port/process-only rule: nothing to resolve
		}
		if ob == "direct" {
			rule["server"] = directResolverTag
		} else {
			rule["server"] = remote
		}
		mirrored = append(mirrored, rule)
	}
	if len(mirrored) > 0 {
		existing, _ := dns["rules"].([]any)
		// User-authored rules keep priority; ours only cover what they left open.
		dns["rules"] = append(existing, mirrored...)
	}

	// (3) unmatched traffic: if the catch-all egresses direct, so must its DNS.
	if catchAllOutbound(rules) == "direct" {
		dns["final"] = directResolverTag
	}

	nd, err := json.Marshal(dns)
	if err != nil {
		return err
	}
	cfg["dns"] = nd

	// (4) every dialing outbound resolves via the resolver its own dial can reach.
	return pinDirectDomainResolver(cfg)
}

// keepDNSSafeTags filters a route rule's rule_set list down to the tags that are
// safe in a DNS rule; nil when nothing survives.
func keepDNSSafeTags(v any, safe map[string]bool) any {
	switch tags := v.(type) {
	case string:
		if safe[tags] {
			return tags
		}
	case []any:
		var kept []any
		for _, t := range tags {
			if s, ok := t.(string); ok && safe[s] {
				kept = append(kept, s)
			}
		}
		if len(kept) > 0 {
			return kept
		}
	}
	return nil
}

// catchAllOutbound returns the outbound of the default-deny catch-all rule (the
// bare network matcher), i.e. where unmatched traffic actually goes.
func catchAllOutbound(rules []json.RawMessage) string {
	idx := catchAllIdx(rules)
	if idx >= len(rules) {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(rules[idx], &m); err != nil {
		return ""
	}
	ob, _ := m["outbound"].(string)
	return ob
}

// pinDirectDomainResolver sets domain_resolver=dns-direct on every outbound that
// dials a destination itself (direct + node protocols), leaving groups alone.
// An outbound that already names a resolver is respected.
func pinDirectDomainResolver(cfg map[string]json.RawMessage) error {
	raw, ok := cfg["outbounds"]
	if !ok {
		return nil
	}
	var outs []map[string]any
	if err := json.Unmarshal(raw, &outs); err != nil {
		return err
	}
	changed := false
	for i, o := range outs {
		typ, _ := o["type"].(string)
		if dialingOutboundSkip[typ] {
			continue
		}
		if _, set := o["domain_resolver"]; set {
			continue
		}
		o["domain_resolver"] = directResolverTag
		outs[i] = o
		changed = true
	}
	if !changed {
		return nil
	}
	nb, err := json.Marshal(outs)
	if err != nil {
		return err
	}
	cfg["outbounds"] = nb
	return nil
}

// splitResolverAddr parses the configured direct resolver into address + port.
// Empty => DefaultDirectResolver. Accepts "223.5.5.5", "223.5.5.5:53",
// "[2400:3200::1]:53" and hostnames (a hostname resolver must be reachable
// without DNS, so an IP is strongly preferred).
func splitResolverAddr(v string) (string, int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return DefaultDirectResolver, 0, nil
	}
	if ip := net.ParseIP(strings.Trim(v, "[]")); ip != nil {
		return ip.String(), 0, nil
	}
	host, portStr, err := net.SplitHostPort(v)
	if err != nil {
		if strings.ContainsAny(v, "/ :") {
			return "", 0, fmt.Errorf("invalid direct resolver %q", v)
		}
		return v, 0, nil // bare hostname
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid direct resolver port in %q", v)
	}
	if host == "" {
		return "", 0, fmt.Errorf("invalid direct resolver %q", v)
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), port, nil
	}
	return host, port, nil
}

// assertDirectResolverSplit fails when a proxy-detoured resolver is in charge of
// direct dials — the state that sends domestic traffic to overseas CDN edges.
func assertDirectResolverSplit(cfg map[string]json.RawMessage, d apitypes.DNSConfig) error {
	if d.DisableDirectSplit {
		return nil
	}
	dnsRaw, ok := cfg["dns"]
	if !ok {
		return nil
	}
	var dns map[string]any
	if err := json.Unmarshal(dnsRaw, &dns); err != nil {
		return err
	}
	proxyDetour := map[string]bool{}
	hasDirectResolver := false
	for _, s := range mapSlice(dns["servers"]) {
		tag, _ := s["tag"].(string)
		det, _ := s["detour"].(string)
		if det == "proxy" {
			proxyDetour[tag] = true
		} else if tag == directResolverTag {
			hasDirectResolver = true
		}
	}
	var route map[string]json.RawMessage
	if raw, ok := cfg["route"]; ok {
		if err := json.Unmarshal(raw, &route); err != nil {
			return err
		}
	}
	var base string
	_ = json.Unmarshal(route["default_domain_resolver"], &base)
	if base == "" {
		base, _ = dns["final"].(string)
	}
	if !proxyDetour[base] {
		return nil // direct dials already resolve off-tunnel
	}
	if !hasDirectResolver {
		return fmt.Errorf("resolver %q is behind the proxy and no %q server exists", base, directResolverTag)
	}
	var outs []map[string]any
	if raw, ok := cfg["outbounds"]; ok {
		if err := json.Unmarshal(raw, &outs); err != nil {
			return err
		}
	}
	for _, o := range outs {
		if typ, _ := o["type"].(string); typ != "direct" {
			continue
		}
		res, _ := o["domain_resolver"].(string)
		if res == "" || proxyDetour[res] {
			return fmt.Errorf("direct outbound %q resolves via %q (behind the proxy)", o["tag"], res)
		}
	}
	return nil
}

// mapSlice coerces a decoded JSON array into []map[string]any, skipping
// non-object members.
func mapSlice(v any) []map[string]any {
	arr, _ := v.([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
