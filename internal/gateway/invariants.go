package gateway

import (
	"encoding/json"
	"fmt"

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
			hc, _ := rs["http_client"].(map[string]any)
			ref, _ := hc["domain_resolver"].(string)
			if ref != "" && !declared[ref] {
				tag, _ := rs["tag"].(string)
				return report(fmt.Sprintf("rule set %q", tag), ref)
			}
		}
	}
	return nil
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
