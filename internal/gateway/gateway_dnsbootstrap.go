package gateway

import (
	"encoding/json"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// healBootstrapDNS fixes the TUN+no-exits DNS blackhole.
//
// Defaults seed DoH to 1.1.1.1 with detour=proxy. With zero applied nodes the
// proxy group is selector[direct], so that DoH is a *direct* dial to Cloudflare.
// On CN networks 1.1.1.1 is commonly unreachable → every hijack-dns lookup
// hangs (including the subscription fetch that would populate the proxy group).
// The old comment "bootstrapping is fine with no nodes" assumed that path
// worked; live ACK nodes proved it does not.
//
// When proxy has no real exit members, force final + default_domain_resolver
// onto dns-direct (223.5.5.5 UDP, no detour). Once exits exist this is a
// no-op and the operator's DoH-via-proxy policy stays.
//
// Skipped when DisableDirectSplit is set — the operator opted out of any
// dns-direct rewrite (same contract as injectDirectDNS).
func healBootstrapDNS(cfg map[string]json.RawMessage, d apitypes.DNSConfig) error {
	if d.DisableDirectSplit {
		return nil
	}
	if !proxyHasOnlyDirect(cfg) {
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
	servers, _ := dns["servers"].([]any)
	detourOf := map[string]string{}
	for _, s := range servers {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := m["tag"].(string)
		det, _ := m["detour"].(string)
		if tag != "" {
			detourOf[tag] = det
		}
	}
	final, _ := dns["final"].(string)
	// Already on a direct-dialed final (e.g. Defaults' ali / udp 223.5.5.5) — leave it.
	if final != "" && detourOf[final] != "proxy" {
		return nil
	}
	hasDirect := false
	for _, s := range servers {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if m["tag"] == directResolverTag {
			hasDirect = true
			break
		}
	}
	if !hasDirect {
		addr, port, err := splitResolverAddr(DefaultDirectResolver)
		if err != nil {
			return err
		}
		srv := map[string]any{"type": "udp", "tag": directResolverTag, "server": addr}
		if port > 0 {
			srv["server_port"] = port
		}
		dns["servers"] = append(servers, srv)
	}
	dns["final"] = directResolverTag
	raw, err := json.Marshal(dns)
	if err != nil {
		return err
	}
	cfg["dns"] = raw
	return setDefaultDomainResolver(cfg, directResolverTag)
}

// proxyHasOnlyDirect reports whether the proxy group has no real exit members
// (selector/urltest whose only outbound is "direct", or missing entirely).
func proxyHasOnlyDirect(cfg map[string]json.RawMessage) bool {
	raw, ok := cfg["outbounds"]
	if !ok {
		return true
	}
	var outs []map[string]any
	if err := json.Unmarshal(raw, &outs); err != nil {
		return true
	}
	var proxy map[string]any
	for _, o := range outs {
		if o["tag"] == ProxyGroupTag {
			proxy = o
			break
		}
	}
	if proxy == nil {
		return true
	}
	members, _ := proxy["outbounds"].([]any)
	if len(members) == 0 {
		return true
	}
	for _, m := range members {
		tag, _ := m.(string)
		if tag != "" && tag != "direct" {
			return false
		}
	}
	return true
}
