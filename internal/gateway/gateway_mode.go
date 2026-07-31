// Capture-mode wiring (manual/system/tun) and the Rule<->Global clash_mode
// toggle, including TUN's local-DNS rewrite/fakeip/default-resolver fixups.
package gateway

import (
	"encoding/json"
	"net/netip"

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
// base config so 127.0.0.1:21584 stays available in every mode.
// tunInboundAddresses is the ONE answer to "which CIDRs does our tun interface
// carry". Both the inbound we build and the prefixes we hand the host-level
// watcher come from here, because the watcher identifies OUR tunnel by address
// rather than by name (a machine can have several utun devices — Tailscale,
// another VPN). A second copy of this list drifts: one already did, and the
// symptom was a tunnel-route-missing alert on every poll of a perfectly healthy
// TUN, because the watcher was looking for a network nobody was using.
func tunInboundAddresses(tun apitypes.TUNConfig) []string {
	if len(tun.Address) > 0 {
		return append([]string(nil), tun.Address...)
	}
	return append([]string(nil), apitypes.DefaultTUNAddresses...)
}

// tunPrefixesOf parses the addresses of a tun config into prefixes, dropping
// anything unparseable (the store validates on write, so this is belt-and-braces).
func tunPrefixesOf(tun apitypes.TUNConfig) []netip.Prefix {
	addrs := tunInboundAddresses(tun)
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func applyMode(cfg map[string]json.RawMessage, mode string, auth apitypes.InboundAuth, tun apitypes.TUNConfig, bind apitypes.InboundListen) error {
	if mode == "" {
		mode = ModeManual
	}
	listen, port := "127.0.0.1", 21584
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
	// The store wins over the base config when it has an opinion. Zero fields
	// mean "no opinion", so a machine that never touched this setting binds
	// exactly where its config.json says, as before.
	if bind.Listen != "" {
		listen = bind.Listen
	}
	if bind.Port != 0 {
		port = bind.Port
	}
	mixed := map[string]any{"type": "mixed", "tag": "mixed-in", "listen": listen, "listen_port": port}
	// Optional auth on the mixed inbound: no credentials leaves it open (no "users"
	// field at all). Several are allowed — one per person or per device, so a leaked
	// one can be revoked without cutting everybody off. sing-box rejects a lone half
	// of a pair, which the store's validation already guards against.
	if creds := auth.Credentials(); len(creds) > 0 {
		list := make([]map[string]any, 0, len(creds))
		for _, c := range creds {
			list = append(list, map[string]any{"username": c.Username, "password": c.Password})
		}
		mixed["users"] = list
	}

	var ins []map[string]any
	switch mode {
	case ModeSystem:
		mixed["set_system_proxy"] = true
		ins = []map[string]any{mixed}
	case ModeTUN:
		ins = []map[string]any{buildTUNInbound(tun), mixed}
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

// buildTUNInbound assembles the sing-box tun inbound. On Linux, AutoRedirect
// (nftables) is what actually pulls Docker/containerd bridge egress into the
// same Permit/detect path as host processes — plain auto_route alone often
// misses forwarded packets. Non-Linux builds omit the field (sing-box rejects
// it there). Address defaults to apitypes.DefaultTUNAddresses so the /30 does
// not collide with Docker's 172.16/12 pools.
func buildTUNInbound(tun apitypes.TUNConfig) map[string]any {
	stack := tun.Stack
	if stack == "" {
		stack = "gvisor"
	}
	tunIn := map[string]any{
		"type": "tun", "tag": "tun-in",
		"address":      tunInboundAddresses(tun),
		"auto_route":   true,
		"strict_route": tun.StrictRoute,
		"stack":        stack,
	}
	if tunAutoRedirectEnabled(tun) {
		tunIn["auto_redirect"] = true
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
	return tunIn
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
