package gateway

import (
	"encoding/json"
	"fmt"

	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// applyInvariants enforces the safety contracts every merged config must
// satisfy. It runs once at the end of buildMergedConfig so individual inject*
// helpers can't leave the box in a mode that blackholes traffic.
//
// Contracts (mutate to fix — never silently widen the ACL allow-set):
//
//  1. TUN DNS: no type=local; final + default_domain_resolver must dial a real
//     upstream (fakeip/hosts alone can't back hijack-dns). Prevents the
//     hijack→system-resolver→TUN feedback loop.
//  2. TUN routing: hijack-dns prelude + auto_detect_interface must be present.
//  3. DNS follows route: when the default resolver sits behind the proxy,
//     direct-routed domains (and every direct dial) must resolve through a
//     directly-dialed resolver instead — otherwise domestic destinations get the
//     exit node's region's CDN answers and are dialed direct to the far side of
//     the planet. See injectDirectDNS.
//  4. Proxy groups: when ≥1 non-loopback node exists, Auto / Overseas / country
//     urltest groups must not list loopback members (dead WARP etc.). A Local
//     selector holds those tags. Idempotent with buildProxyGroups.
func applyInvariants(cfg map[string]json.RawMessage, mode string, loopback map[string]bool, dns apitypes.DNSConfig, dnsSafeTags map[string]bool) error {
	if mode == ModeTUN {
		if err := sanitizeTunDNS(cfg); err != nil {
			return fmt.Errorf("invariant tun-dns: %w", err)
		}
		if err := ensureTunHijackAndInterface(cfg); err != nil {
			return fmt.Errorf("invariant tun-route: %w", err)
		}
		if err := assertDNSRealUpstream(cfg); err != nil {
			return fmt.Errorf("invariant tun-dns-assert: %w", err)
		}
	}
	// After the TUN DNS fixups (they choose the resolver this splits away from)
	// and after every route inject: the split mirrors the final route table.
	if err := injectDirectDNS(cfg, dns, dnsSafeTags); err != nil {
		return fmt.Errorf("invariant dns-follows-route: %w", err)
	}
	if err := assertDirectResolverSplit(cfg, dns); err != nil {
		return fmt.Errorf("invariant dns-follows-route-assert: %w", err)
	}
	if err := repairProxyGroupLoopbacks(cfg, loopback); err != nil {
		return fmt.Errorf("invariant proxy-groups: %w", err)
	}
	if err := assertResolverReferences(cfg); err != nil {
		return fmt.Errorf("invariant resolver-refs: %w", err)
	}
	if err := assertRuleSetReferences(cfg); err != nil {
		return fmt.Errorf("invariant rule-set-refs: %w", err)
	}
	return nil
}

// assertResolverReferences fails the build when anything names a DNS server that
// does not exist.
//
// One injector wrote `domain_resolver: dns-direct` on every remote rule set;
// another creates that server, but only when the default resolver sits behind
// the proxy. On a fresh install — resolver `local`, no detour — nothing created
// it, and sing-box refused to start the box with eight repetitions of "domain
// resolver not found: dns-direct". Switching to Split was what surfaced it,
// because that is what seeds the catalog's remote rule sets, so *every fresh
// install* hit it and the machines that worked were the ones somebody had
// configured a proxied resolver on.
//
// The rule that prevents the whole class: whoever creates a tag owns every
// reference to it. This is the enforcement — a dangling reference now fails
// where the config is built, naming the tag and who pointed at it, instead of
// eight lines deep in a box that will not start.
func assertResolverReferences(cfg map[string]json.RawMessage) error {
	declared := map[string]bool{}
	if raw, ok := cfg["dns"]; ok {
		var dns map[string]any
		if err := json.Unmarshal(raw, &dns); err != nil {
			return err
		}
		for _, s := range mapSlice(dns["servers"]) {
			if tag, _ := s["tag"].(string); tag != "" {
				declared[tag] = true
			}
		}
	}
	report := func(who, ref string) error {
		return fmt.Errorf("%s names DNS server %q, which nothing declares "+
			"(declared: %v) — the injector that creates a resolver must be the one that "+
			"references it", who, ref, sortedTags(declared))
	}

	var outs []map[string]any
	if raw, ok := cfg["outbounds"]; ok {
		if err := json.Unmarshal(raw, &outs); err != nil {
			return err
		}
	}
	for _, o := range outs {
		ref, _ := o["domain_resolver"].(string)
		if ref != "" && !declared[ref] {
			tag, _ := o["tag"].(string)
			return report(fmt.Sprintf("outbound %q", tag), ref)
		}
	}

	// http_clients is a third namespace that can dangle the same way, and it also
	// declares the tags rule-set descriptors point at — so both directions are
	// checked here: its resolver must exist, and the clients it declares are the
	// only ones a descriptor may name.
	httpClients := map[string]bool{}
	if raw, ok := cfg["http_clients"]; ok {
		var clients []map[string]any
		if err := json.Unmarshal(raw, &clients); err != nil {
			return err
		}
		for _, c := range clients {
			tag, _ := c["tag"].(string)
			if tag != "" {
				httpClients[tag] = true
			}
			ref, _ := c["domain_resolver"].(string)
			if ref != "" && !declared[ref] {
				return report(fmt.Sprintf("http client %q", tag), ref)
			}
		}
	}

	if raw, ok := cfg["route"]; ok {
		var route map[string]json.RawMessage
		if err := json.Unmarshal(raw, &route); err != nil {
			return err
		}
		var base string
		_ = json.Unmarshal(route["default_domain_resolver"], &base)
		if base != "" && !declared[base] {
			return report("route.default_domain_resolver", base)
		}
		var sets []map[string]any
		if rsRaw, ok := route["rule_set"]; ok {
			if err := json.Unmarshal(rsRaw, &sets); err != nil {
				return err
			}
		}
		for _, rs := range sets {
			tag, _ := rs["tag"].(string)
			switch hc := rs["http_client"].(type) {
			case map[string]any:
				// An empty object is not a dangling reference, it is a silent one: it
				// means "use the default outbound", and route.final is `blocked`, so the
				// gateway dials its own policy downloads into the block outbound and
				// refuses to start. Schema-valid, released three times.
				if len(hc) == 0 {
					return fmt.Errorf("rule set %q has an empty http_client, which upstream reads as "+
						"\"use the default outbound\" — and the default outbound is route.final (%q), so the "+
						"fetch is dialed into it instead of out", tag, routeFinalTag(route))
				}
				if ref, _ := hc["domain_resolver"].(string); ref != "" && !declared[ref] {
					return report(fmt.Sprintf("rule set %q", tag), ref)
				}
			case string:
				if !httpClients[hc] {
					return fmt.Errorf("rule set %q fetches via http client %q, which no http_clients entry "+
						"declares (declared: %v) — the injector that creates a client must be the one that "+
						"references it", tag, hc, sortedTags(httpClients))
				}
			}
		}
	}
	return nil
}

// routeFinalTag reports the configured catch-all outbound, for error messages
// that need to name the outbound a fetch would otherwise be dialed into.
func routeFinalTag(route map[string]json.RawMessage) string {
	var final string
	_ = json.Unmarshal(route["final"], &final)
	if final == "" {
		return "the first outbound"
	}
	return final
}

// sortedTags renders a tag set for an error message, stably.
func sortedTags(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ensureTunHijackAndInterface guarantees the TUN prelude pieces exist even if
// ensureTunExtras was skipped or a future inject wiped them.
func ensureTunHijackAndInterface(cfg map[string]json.RawMessage) error {
	routeRaw, ok := cfg["route"]
	if !ok {
		return fmt.Errorf("route missing")
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(routeRaw, &route); err != nil {
		return err
	}
	route["auto_detect_interface"] = json.RawMessage("true")

	var rules []json.RawMessage
	if raw, ok := route["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return err
		}
	}
	hasHijack, sniffIdx := false, -1
	for i, r := range rules {
		var meta struct {
			Action              string `json:"action"`
			OverrideDestination bool   `json:"override_destination"`
		}
		_ = json.Unmarshal(r, &meta)
		if meta.Action == "hijack-dns" {
			hasHijack = true
		}
		if meta.Action == "sniff" && sniffIdx < 0 {
			sniffIdx = i
			// TUN: client may have resolved via MagicDNS/ISP (bypasses hijack) to a
			// GFW-poisoned IP. Override destination with sniffed SNI so dial uses
			// sing-box DNS (DoH via proxy) instead of the poisoned address.
			if !meta.OverrideDestination {
				var m map[string]any
				if err := json.Unmarshal(r, &m); err == nil {
					m["override_destination"] = true
					if nb, err := json.Marshal(m); err == nil {
						rules[i] = nb
					}
				}
			}
		}
	}
	if !hasHijack {
		hj, _ := json.Marshal(map[string]any{"protocol": "dns", "action": "hijack-dns"})
		at := sniffIdx + 1
		if at < 0 {
			at = 0
		}
		merged := make([]json.RawMessage, 0, len(rules)+1)
		merged = append(merged, rules[:at]...)
		merged = append(merged, hj)
		merged = append(merged, rules[at:]...)
		rules = merged
	}
	nr, err := json.Marshal(rules)
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

// assertDNSRealUpstream fails if TUN still has a looping/synth-only DNS final.
func assertDNSRealUpstream(cfg map[string]json.RawMessage) error {
	raw, ok := cfg["dns"]
	if !ok {
		return fmt.Errorf("dns block missing under TUN")
	}
	var dns map[string]any
	if err := json.Unmarshal(raw, &dns); err != nil {
		return err
	}
	servers, _ := dns["servers"].([]any)
	tags := map[string]string{}
	for _, s := range servers {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := m["tag"].(string)
		typ, _ := m["type"].(string)
		if typ == "local" {
			return fmt.Errorf("dns type=local still present (tag=%q)", tag)
		}
		if tag != "" {
			tags[tag] = typ
		}
	}
	final, _ := dns["final"].(string)
	if final == "" {
		return fmt.Errorf("dns final empty under TUN")
	}
	typ := tags[final]
	if typ == "" || typ == "local" || typ == "fakeip" || typ == "hosts" {
		return fmt.Errorf("dns final %q has type %q (need real upstream)", final, typ)
	}

	var route map[string]json.RawMessage
	if err := json.Unmarshal(cfg["route"], &route); err != nil {
		return err
	}
	var resolver string
	_ = json.Unmarshal(route["default_domain_resolver"], &resolver)
	if resolver == "" {
		return fmt.Errorf("default_domain_resolver missing under TUN")
	}
	if rtyp := tags[resolver]; rtyp == "" || rtyp == "local" || rtyp == "fakeip" || rtyp == "hosts" {
		return fmt.Errorf("default_domain_resolver %q has type %q", resolver, rtyp)
	}
	return nil
}

// repairProxyGroupLoopbacks strips loopback members from Auto / Overseas /
// country urltest groups when at least one remote member exists, and ensures a
// Local selector holds the loopback tags.
func repairProxyGroupLoopbacks(cfg map[string]json.RawMessage, loopback map[string]bool) error {
	if len(loopback) == 0 {
		return nil
	}
	raw, ok := cfg["outbounds"]
	if !ok {
		return nil
	}
	var outs []map[string]any
	if err := json.Unmarshal(raw, &outs); err != nil {
		return err
	}

	localMembers := make([]any, 0, len(loopback))
	for tag := range loopback {
		localMembers = append(localMembers, tag)
	}

	hasRemote := false
	localIdx := -1
	for i, o := range outs {
		tag, _ := o["tag"].(string)
		typ, _ := o["type"].(string)
		members, _ := o["outbounds"].([]any)
		switch {
		case tag == "Auto":
			var kept []any
			for _, m := range members {
				s, _ := m.(string)
				if loopback[s] {
					continue
				}
				kept = append(kept, m)
			}
			if len(kept) > 0 {
				hasRemote = true
				o["outbounds"] = kept
				outs[i] = o
			}
		case tag == "Local":
			localIdx = i
		case tag == ProxyGroupTag:
			// handled after Local insert
		case typ == "urltest" || typ == "selector":
			var kept []any
			changed := false
			for _, m := range members {
				s, _ := m.(string)
				if loopback[s] {
					changed = true
					continue
				}
				kept = append(kept, m)
			}
			if changed && len(kept) > 0 {
				o["outbounds"] = kept
				outs[i] = o
			}
		}
	}

	if !hasRemote {
		nb, err := json.Marshal(outs)
		if err != nil {
			return err
		}
		cfg["outbounds"] = nb
		return nil
	}

	if localIdx < 0 {
		local := map[string]any{"type": "selector", "tag": "Local", "outbounds": localMembers}
		insertAt := len(outs)
		for i, o := range outs {
			if o["tag"] == ProxyGroupTag {
				insertAt = i
				break
			}
		}
		outs = append(outs[:insertAt], append([]map[string]any{local}, outs[insertAt:]...)...)
	}

	for i, o := range outs {
		if o["tag"] != ProxyGroupTag {
			continue
		}
		all, _ := o["outbounds"].([]any)
		if containsAnyStr(all, "Local") {
			break
		}
		newAll := make([]any, 0, len(all)+1)
		for _, m := range all {
			newAll = append(newAll, m)
			if m == "Auto" {
				newAll = append(newAll, "Local")
			}
		}
		if !containsAnyStr(newAll, "Local") {
			newAll = append(newAll, "Local")
		}
		o["outbounds"] = newAll
		outs[i] = o
		break
	}

	nb, err := json.Marshal(outs)
	if err != nil {
		return err
	}
	cfg["outbounds"] = nb
	return nil
}

func containsAnyStr(all []any, want string) bool {
	for _, m := range all {
		if m == want {
			return true
		}
	}
	return false
}

// declaredRuleSetTags lists the rule_set tags actually present in the config, so
// other injectors can avoid emitting a reference to one that is not.
//
// Read from the config rather than from the store, because those are different
// things: injectRuleSets skips disabled entries, so the store may list a set the
// box will not have.
func declaredRuleSetTags(cfg map[string]json.RawMessage) map[string]bool {
	out := map[string]bool{}
	raw, ok := cfg["route"]
	if !ok {
		return out
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(raw, &route); err != nil {
		return out
	}
	var sets []map[string]any
	if rs, ok := route["rule_set"]; ok {
		if err := json.Unmarshal(rs, &sets); err != nil {
			return out
		}
	}
	for _, s := range sets {
		if tag, _ := s["tag"].(string); tag != "" {
			out[tag] = true
		}
	}
	return out
}

// willDeclareRuleSetTags is the set of rule_set tags the finished config will
// have: the enabled entries injectRuleSets is about to register, plus any the base
// config already carries.
//
// Needed because the injectors do not run in dependency order — injectDNS runs
// before injectRuleSets — so anything that has to agree with the rule sets cannot
// learn them by reading the config at that point.
func willDeclareRuleSetTags(cfg map[string]json.RawMessage, sets ruleset.Sets) map[string]bool {
	out := declaredRuleSetTags(cfg)
	for _, rs := range sets.Sets {
		if rs.Enabled && rs.Tag != "" {
			out[rs.Tag] = true
		}
	}
	return out
}

// assertRuleSetReferences refuses a config where anything names a rule set the
// config does not declare.
//
// Same class as assertResolverReferences, one namespace over: sing-box answers a
// dangling rule_set tag with "rule-set not found: X" at Start, which is past every
// schema check and therefore past every test in this package that stops at
// unmarshalling. Failing the rebuild instead means the previous config keeps
// running and the operator gets a sentence naming the tag.
func assertRuleSetReferences(cfg map[string]json.RawMessage) error {
	declared := declaredRuleSetTags(cfg)
	report := func(who, tag string) error {
		return fmt.Errorf("%s names rule set %q, which nothing declares (declared: %v) — "+
			"the injector that registers a rule set must be the one that references it",
			who, tag, sortedTags(declared))
	}

	if raw, ok := cfg["dns"]; ok {
		var dns map[string]json.RawMessage
		if err := json.Unmarshal(raw, &dns); err != nil {
			return err
		}
		var rules []map[string]any
		if r, ok := dns["rules"]; ok {
			if err := json.Unmarshal(r, &rules); err != nil {
				return err
			}
		}
		for i, r := range rules {
			for _, tag := range strSliceOf(r["rule_set"]) {
				if !declared[tag] {
					return report(fmt.Sprintf("dns.rules[%d]", i), tag)
				}
			}
		}
	}

	if raw, ok := cfg["route"]; ok {
		var route map[string]json.RawMessage
		if err := json.Unmarshal(raw, &route); err != nil {
			return err
		}
		var rules []map[string]any
		if r, ok := route["rules"]; ok {
			if err := json.Unmarshal(r, &rules); err != nil {
				return err
			}
		}
		for i, r := range rules {
			if err := checkRuleSetRefs(fmt.Sprintf("route.rules[%d]", i), r, declared, report); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkRuleSetRefs walks a route rule and its logical sub-rules, which is where
// the Permit gate keeps its rule_set matchers.
func checkRuleSetRefs(who string, r map[string]any, declared map[string]bool, report func(string, string) error) error {
	for _, tag := range strSliceOf(r["rule_set"]) {
		if !declared[tag] {
			return report(who, tag)
		}
	}
	subs, _ := r["rules"].([]any)
	for i, sr := range subs {
		m, ok := sr.(map[string]any)
		if !ok {
			continue
		}
		if err := checkRuleSetRefs(fmt.Sprintf("%s.rules[%d]", who, i), m, declared, report); err != nil {
			return err
		}
	}
	return nil
}

// strSliceOf reads a JSON string array that may be absent or a bare string.
func strSliceOf(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
