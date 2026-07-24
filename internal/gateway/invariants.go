package gateway

import (
	"encoding/json"
	"fmt"
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
//  3. Proxy groups: when ≥1 non-loopback node exists, Auto / Overseas / country
//     urltest groups must not list loopback members (dead WARP etc.). A Local
//     selector holds those tags. Idempotent with buildProxyGroups.
func applyInvariants(cfg map[string]json.RawMessage, mode string, loopback map[string]bool) error {
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
	if err := repairProxyGroupLoopbacks(cfg, loopback); err != nil {
		return fmt.Errorf("invariant proxy-groups: %w", err)
	}
	return nil
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
			Action string `json:"action"`
		}
		_ = json.Unmarshal(r, &meta)
		if meta.Action == "hijack-dns" {
			hasHijack = true
		}
		if meta.Action == "sniff" && sniffIdx < 0 {
			sniffIdx = i
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
