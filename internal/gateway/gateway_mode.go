// Capture-mode wiring (manual/system/tun) and the Rule<->Global clash_mode
// toggle, including TUN's local-DNS rewrite/fakeip/default-resolver fixups.
package gateway

import (
	"encoding/json"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// injectClashModeGlobal adds a route rule that routes everything to the proxy
// group ONLY when the live Clash mode is "Global" — a no-rebuild toggle that
// turns the ACL default-deny OFF (unlisted traffic egresses via proxy instead
// of being blocked). It runs BEFORE injectAllow, so it lands just above the ACL
// gate and BELOW the security floor (blacklist / rule-set-block /
// process+device gates): in Global mode traffic that clears the floor matches
// here and routes to proxy before the gate can block it, while blacklisted and
// unknown-process/device connections are still rejected. In "Rule" mode the
// rule is inert (clash_mode mismatch, matched case-insensitively) and the gate
// applies unchanged. sing-box derives the selectable mode list from the
// clash_mode values present in the rules, so this alone exposes ["Global","Rule"].
func injectClashModeGlobal(cfg map[string]json.RawMessage, dataDir string) error {
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
	// Insert right before the default-deny catch-all (the bare network matcher).
	catchIdx := catchAllIdx(rules)
	globalRule, _ := json.Marshal(map[string]any{"clash_mode": "Global", "action": "route", "outbound": ProxyGroupTag})
	merged := make([]json.RawMessage, 0, len(rules)+1)
	merged = append(merged, rules[:catchIdx]...)
	merged = append(merged, globalRule)
	merged = append(merged, rules[catchIdx:]...)
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
	// Seed the safe default mode; cache_file persists the live selection across
	// restarts (sing-box loads it on start if present in the mode list).
	if err := setClashDefaultMode(cfg, "Rule"); err != nil {
		return err
	}
	return ensureCacheFile(cfg, dataDir)
}

// setClashDefaultMode sets experimental.clash_api.default_mode (the mode used on
// first run, before any cached selection). No-op if clash_api is absent.
func setClashDefaultMode(cfg map[string]json.RawMessage, mode string) error {
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
	if _, set := ca["default_mode"]; !set {
		ca["default_mode"] = mode
	}
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

// applyMode rewrites the inbounds (and, for TUN, adds DNS + hijack) to match the
// requested capture mode. The mixed inbound's listen/port is preserved from the
// base config so 127.0.0.1:17070 stays available in every mode.
func applyMode(cfg map[string]json.RawMessage, mode string, auth apitypes.InboundAuth, tun apitypes.TUNConfig) error {
	if mode == "" {
		mode = ModeManual
	}
	listen, port := "127.0.0.1", 17070
	if raw, ok := cfg["inbounds"]; ok {
		var existing []map[string]any
		if err := json.Unmarshal(raw, &existing); err == nil {
			for _, in := range existing {
				switch in["type"] {
				case "mixed", "socks", "http":
					if l, ok := in["listen"].(string); ok && l != "" {
						listen = l
					}
					if p, ok := in["listen_port"].(float64); ok {
						port = int(p)
					}
				}
			}
		}
	}
	mixed := map[string]any{"type": "mixed", "tag": "mixed-in", "listen": listen, "listen_port": port}
	// Optional auth: require a username/password on the mixed inbound. Both empty
	// leaves it open (no "users" field). sing-box rejects a lone half of the pair,
	// which the store's validation already guards against.
	if auth.Username != "" && auth.Password != "" {
		mixed["users"] = []map[string]any{{"username": auth.Username, "password": auth.Password}}
	}

	var ins []map[string]any
	switch mode {
	case ModeSystem:
		mixed["set_system_proxy"] = true
		ins = []map[string]any{mixed}
	case ModeTUN:
		stack := tun.Stack
		if stack == "" {
			stack = "gvisor"
		}
		tunIn := map[string]any{
			"type": "tun", "tag": "tun-in",
			"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route":   true,
			"strict_route": tun.StrictRoute,
			"stack":        stack,
		}
		if tun.MTU > 0 {
			tunIn["mtu"] = tun.MTU
		}
		if len(tun.ExcludePackage) > 0 {
			tunIn["exclude_package"] = tun.ExcludePackage
		}
		if len(tun.IncludePackage) > 0 {
			tunIn["include_package"] = tun.IncludePackage
		}
		ins = []map[string]any{tunIn, mixed}
		if err := ensureTunExtras(cfg); err != nil {
			return err
		}
	default: // ModeManual
		ins = []map[string]any{mixed}
	}
	raw, err := json.Marshal(ins)
	if err != nil {
		return err
	}
	cfg["inbounds"] = raw
	return nil
}

// ensureTunExtras adds the pieces TUN capture needs that the base client config
// omits. DNS sanitization + hijack/auto_detect are owned by the shared
// invariant helpers (also re-run at the end of buildMergedConfig).
func ensureTunExtras(cfg map[string]json.RawMessage) error {
	if err := sanitizeTunDNS(cfg); err != nil {
		return err
	}
	return ensureTunHijackAndInterface(cfg)
}

// tunDNSFallback is substituted for dns type=local under TUN.
// Must NOT be a mainland UDP resolver (223.5.5.5 etc.): those return
// GFW-poisoned answers for Google/YouTube. DoH via the proxy group yields
// clean A/AAAA; bootstrap uses the literal IP so we don't need system DNS.
const tunDNSFallbackTag = "tun-dns"

func tunDNSFallbackServer() map[string]any {
	return map[string]any{
		"type":   "https",
		"tag":    tunDNSFallbackTag,
		"server": "8.8.8.8", // dns.google anycast — no name lookup to bootstrap
		"detour": "proxy",
	}
}

// sanitizeTunDNS ensures TUN mode never keeps a dns type=local server (or a
// final/default_domain_resolver pointing at one). Missing dns → install DoH via
// proxy; existing local servers are rewritten in place (same tag) so user
// rules/final that reference the tag keep working.
func sanitizeTunDNS(cfg map[string]json.RawMessage) error {
	fallback := tunDNSFallbackServer()

	raw, ok := cfg["dns"]
	if !ok {
		dns, _ := json.Marshal(map[string]any{
			"servers": []map[string]any{fallback},
			"final":   tunDNSFallbackTag,
		})
		cfg["dns"] = dns
		return setDefaultDomainResolver(cfg, tunDNSFallbackTag)
	}

	var dns map[string]any
	if err := json.Unmarshal(raw, &dns); err != nil {
		return err
	}
	servers, _ := dns["servers"].([]any)
	changed := false
	firstReal := ""
	out := make([]any, 0, len(servers)+1)
	for _, s := range servers {
		m, ok := s.(map[string]any)
		if !ok {
			out = append(out, s)
			continue
		}
		typ, _ := m["type"].(string)
		tag, _ := m["tag"].(string)
		if typ == "local" {
			if tag == "" {
				tag = tunDNSFallbackTag
			}
			repl := tunDNSFallbackServer()
			repl["tag"] = tag
			out = append(out, repl)
			if firstReal == "" {
				firstReal = tag
			}
			changed = true
			continue
		}
		if typ != "fakeip" && typ != "hosts" && tag != "" && firstReal == "" {
			firstReal = tag
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		out = []any{fallback}
		firstReal = tunDNSFallbackTag
		changed = true
	}
	if firstReal == "" {
		// Only synth servers left — append a real upstream the resolver can use.
		out = append(out, fallback)
		firstReal = tunDNSFallbackTag
		changed = true
	}
	final, _ := dns["final"].(string)
	finalType := ""
	for _, s := range out {
		if m, ok := s.(map[string]any); ok && m["tag"] == final {
			finalType, _ = m["type"].(string)
			break
		}
	}
	// Under TUN, final must dial a real upstream. type=local loops; fakeip/hosts
	// synthesize answers and can't back default_domain_resolver / hijack-dns.
	if final == "" || finalType == "" || finalType == "local" || finalType == "fakeip" || finalType == "hosts" {
		dns["final"] = firstReal
		changed = true
	}
	if !changed {
		// Still refresh default_domain_resolver in case it pointed at local.
		if res, _ := dns["final"].(string); res != "" {
			return setDefaultDomainResolver(cfg, res)
		}
		return nil
	}
	dns["servers"] = out
	b, err := json.Marshal(dns)
	if err != nil {
		return err
	}
	cfg["dns"] = b
	res, _ := dns["final"].(string)
	return setDefaultDomainResolver(cfg, res)
}
