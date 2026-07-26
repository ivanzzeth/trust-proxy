// Security floor: Clash API secret injection, management-port bypass (L0),
// blacklist reject rules, and the process/device allow-floor (L1).
package gateway

import (
	"encoding/json"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/quarantine"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
)

// injectClashSecret sets experimental.clash_api.secret (so the secret isn't
// baked into the repo's config; serve resolves/generates it at runtime).
func injectClashSecret(cfg map[string]json.RawMessage, secret string) error {
	if secret == "" {
		return nil
	}
	expRaw, ok := cfg["experimental"]
	if !ok {
		return nil
	}
	var exp map[string]json.RawMessage
	if err := json.Unmarshal(expRaw, &exp); err != nil {
		return err
	}
	caRaw, ok := exp["clash_api"]
	if !ok {
		return nil
	}
	var ca map[string]any
	if err := json.Unmarshal(caRaw, &ca); err != nil {
		return err
	}
	ca["secret"] = secret
	newCA, err := json.Marshal(ca)
	if err != nil {
		return err
	}
	exp["clash_api"] = newCA
	newExp, err := json.Marshal(exp)
	if err != nil {
		return err
	}
	cfg["experimental"] = newExp
	return nil
}

// injectManagement inserts a top-priority allow (right after the prelude, above
// even the blacklist) that routes traffic whose SOURCE port is a management port
// straight to direct. That is exactly the box's own SSH/API response traffic —
// so a TUN/system-proxy capture + default-deny can't sever remote management.
// Using source_port (not dest port) means it does NOT open arbitrary egress to
// those ports; it only rescues locally-originated responses.
func injectManagement(cfg map[string]json.RawMessage, ports []int) error {
	if len(ports) == 0 {
		return nil
	}
	routeRaw, ok := cfg["route"]
	if !ok {
		return nil
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(routeRaw, &route); err != nil {
		return err
	}
	var rules []json.RawMessage
	if raw, ok := route["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return err
		}
	}
	preludeEnd := 0
	for preludeEnd < len(rules) {
		var m struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(rules[preludeEnd], &m)
		if m.Action == "sniff" || m.Action == "hijack-dns" {
			preludeEnd++
			continue
		}
		break
	}
	rule, _ := json.Marshal(map[string]any{"source_port": ports, "action": "route", "outbound": "direct"})
	merged := make([]json.RawMessage, 0, len(rules)+1)
	merged = append(merged, rules[:preludeEnd]...)
	merged = append(merged, rule)
	merged = append(merged, rules[preludeEnd:]...)
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

// injectBlacklist inserts reject rules for explicitly denied destinations right
// after the prelude (leading sniff/hijack-dns rules) and before any allow rule,
// so a blacklisted target is rejected first — even if it is also whitelisted or
// matched by an allow rule-set. Emits one rule per matcher kind present; skips
// empty kinds.
func injectBlacklist(cfg map[string]json.RawMessage, bl blacklist.Rules) error {
	routeRaw, ok := cfg["route"]
	if !ok {
		return nil
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(routeRaw, &route); err != nil {
		return err
	}
	var rules []json.RawMessage
	if raw, ok := route["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return err
		}
	}

	var reject []json.RawMessage
	if sfx, rgx := splitDomainMatchers(bl.Domains); len(sfx) > 0 || len(rgx) > 0 {
		if len(sfx) > 0 {
			r, _ := json.Marshal(map[string]any{"domain_suffix": sfx, "action": "reject"})
			reject = append(reject, r)
		}
		if len(rgx) > 0 {
			r, _ := json.Marshal(map[string]any{"domain_regex": rgx, "action": "reject"})
			reject = append(reject, r)
		}
	}
	if len(bl.Keywords) > 0 {
		r, _ := json.Marshal(map[string]any{"domain_keyword": bl.Keywords, "action": "reject"})
		reject = append(reject, r)
	}
	if len(bl.Regexes) > 0 {
		r, _ := json.Marshal(map[string]any{"domain_regex": bl.Regexes, "action": "reject"})
		reject = append(reject, r)
	}
	if len(bl.IPs) > 0 {
		r, _ := json.Marshal(map[string]any{"ip_cidr": bl.IPs, "action": "reject"})
		reject = append(reject, r)
	}
	if len(reject) == 0 {
		return nil
	}

	// Insert right after the prelude (leading sniff/hijack-dns rules), which is
	// above every allow rule and thus wins under sing-box's first-match routing.
	preludeEnd := 0
	for preludeEnd < len(rules) {
		var meta struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(rules[preludeEnd], &meta)
		if meta.Action == "sniff" || meta.Action == "hijack-dns" {
			preludeEnd++
			continue
		}
		break
	}
	merged := make([]json.RawMessage, 0, len(rules)+len(reject))
	merged = append(merged, rules[:preludeEnd]...)
	merged = append(merged, reject...)
	merged = append(merged, rules[preludeEnd:]...)

	newRules, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	route["rules"] = newRules
	newRoute, err := json.Marshal(route)
	if err != nil {
		return err
	}
	cfg["route"] = newRoute
	return nil
}

// injectProcessDeviceFloor emits the opt-in anti-exfil gates as L1 floor rejects
// (inserted right after the prelude, above the ACL gate). If a process
// allow-list is set, any process NOT in it is rejected; if a device (source)
// allow-list is set, any source IP NOT in it is rejected. Empty lists emit
// nothing. These use `reject` (they short-circuit before the destination allow
// decision): a binary/device that isn't explicitly allowed never egresses.
// Entries with a path separator match process_path; others match process_name.
func injectProcessDeviceFloor(cfg map[string]json.RawMessage, wl whitelist.Rules) error {
	if len(wl.Processes) == 0 && len(wl.Devices) == 0 {
		return nil
	}
	routeRaw, ok := cfg["route"]
	if !ok {
		return nil
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(routeRaw, &route); err != nil {
		return err
	}
	var rules []json.RawMessage
	if raw, ok := route["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return err
		}
	}

	var floor []json.RawMessage
	if len(wl.Processes) > 0 {
		var names, paths []string
		for _, p := range wl.Processes {
			if strings.ContainsAny(p, "/\\") {
				paths = append(paths, p)
			} else {
				names = append(names, p)
			}
		}
		rule := map[string]any{"invert": true, "action": "reject"}
		if len(names) > 0 {
			rule["process_name"] = names
		}
		if len(paths) > 0 {
			rule["process_path"] = paths
		}
		r, _ := json.Marshal(rule)
		floor = append(floor, r)
	}
	if len(wl.Devices) > 0 {
		r, _ := json.Marshal(map[string]any{"source_ip_cidr": wl.Devices, "invert": true, "action": "reject"})
		floor = append(floor, r)
	}

	at := preludeLen(rules)
	merged := make([]json.RawMessage, 0, len(rules)+len(floor))
	merged = append(merged, rules[:at]...)
	merged = append(merged, floor...)
	merged = append(merged, rules[at:]...)
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

// injectQuarantine rejects destinations the gateway blocked by itself (threat
// intel, exfil disposal). It sits in the same L1 floor as the deny list and
// above every allow rule, but comes from its own store so a posture switch or
// profile activation — which replace the deny list wholesale — cannot silently
// un-block something the gateway quarantined.
func injectQuarantine(cfg map[string]json.RawMessage, q quarantine.List) error {
	domains, ips := q.Domains(), q.IPs()
	if len(domains) == 0 && len(ips) == 0 {
		return nil
	}
	routeRaw, ok := cfg["route"]
	if !ok {
		return nil
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(routeRaw, &route); err != nil {
		return err
	}
	var rules []json.RawMessage
	if raw, ok := route["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return err
		}
	}

	var reject []json.RawMessage
	if sfx, rgx := splitDomainMatchers(domains); len(sfx) > 0 || len(rgx) > 0 {
		if len(sfx) > 0 {
			r, _ := json.Marshal(map[string]any{"domain_suffix": sfx, "action": "reject"})
			reject = append(reject, r)
		}
		if len(rgx) > 0 {
			r, _ := json.Marshal(map[string]any{"domain_regex": rgx, "action": "reject"})
			reject = append(reject, r)
		}
	}
	if len(ips) > 0 {
		r, _ := json.Marshal(map[string]any{"ip_cidr": ips, "action": "reject"})
		reject = append(reject, r)
	}

	at := preludeLen(rules)
	merged := make([]json.RawMessage, 0, len(rules)+len(reject))
	merged = append(merged, rules[:at]...)
	merged = append(merged, reject...)
	merged = append(merged, rules[at:]...)
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
