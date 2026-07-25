// DNS injection (typed servers/rules/strategy, fakeip persistence, and the
// default_domain_resolver wiring routing outbound lookups through it).
package gateway

import (
	"encoding/json"
	"path/filepath"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// injectDNS builds the sing-box dns block from our config. Empty servers => no
// dns block (keep sing-box defaults / TUN's injected resolver). Server types map
// straight to sing-box 1.12+ typed DNS servers; local needs no address.
func injectDNS(cfg map[string]json.RawMessage, d apitypes.DNSConfig, dataDir string) error {
	if len(d.Servers) == 0 {
		return nil
	}
	servers := make([]map[string]any, 0, len(d.Servers))
	usesFakeIP := false
	for _, s := range d.Servers {
		m := map[string]any{"type": s.Type, "tag": s.Tag}
		switch s.Type {
		case "local":
			// no address
		case "fakeip":
			// fakeip synthesizes answers from a private range — no address/detour.
			inet4 := s.Inet4Range
			if inet4 == "" {
				inet4 = "198.18.0.0/15"
			}
			inet6 := s.Inet6Range
			if inet6 == "" {
				inet6 = "fc00::/18"
			}
			m["inet4_range"] = inet4
			m["inet6_range"] = inet6
			usesFakeIP = true
		case "hosts":
			// hosts answers from a predefined map — no address/detour.
			if len(s.Records) > 0 {
				m["predefined"] = s.Records
			}
		default:
			m["server"] = s.Server
			if s.Port > 0 {
				m["server_port"] = s.Port
			}
			// Only "proxy" is a meaningful detour; "direct"/"" dial directly
			// (sing-box rejects a detour to the empty `direct` outbound).
			if s.Detour == "proxy" {
				m["detour"] = "proxy"
			}
		}
		servers = append(servers, m)
	}
	rules := make([]map[string]any, 0, len(d.Rules))
	for _, r := range d.Rules {
		if r.Server == "" || (len(r.DomainSuffix) == 0 && len(r.RuleSet) == 0) {
			continue // never emit an empty-matcher rule
		}
		m := map[string]any{"server": r.Server}
		if len(r.DomainSuffix) > 0 {
			m["domain_suffix"] = r.DomainSuffix
		}
		if len(r.RuleSet) > 0 {
			m["rule_set"] = r.RuleSet
		}
		rules = append(rules, m)
	}
	dns := map[string]any{"servers": servers}
	if len(rules) > 0 {
		dns["rules"] = rules
	}
	if d.Final != "" {
		dns["final"] = d.Final
	}
	if d.Strategy != "" {
		dns["strategy"] = d.Strategy
	}
	raw, err := json.Marshal(dns)
	if err != nil {
		return err
	}
	cfg["dns"] = raw

	// fakeip needs its allocations persisted across rebuilds/restarts, otherwise
	// live connections lose their fake<->real mapping. Enable cache_file (with
	// store_fakeip) the same way remote rule_sets do.
	if usesFakeIP {
		if err := ensureCacheFile(cfg, dataDir); err != nil {
			return err
		}
		if err := ensureStoreFakeIP(cfg, dataDir); err != nil {
			return err
		}
	}

	// Route outbound domain resolution through the dns router (required since
	// sing-box 1.12), which also makes every lookup observable in the logs — the
	// hook our DNS-tunnel / DGA detection consumes.
	resolver := d.Final
	if resolver == "" {
		resolver = d.Servers[0].Tag
	}
	// default_domain_resolver must resolve to real addresses: a fakeip/hosts
	// server can't serve as the outbound resolver. Fall back to the first
	// server that returns real answers.
	if isSynthResolver(d, resolver) {
		resolver = ""
		for _, s := range d.Servers {
			if s.Type != "fakeip" && s.Type != "hosts" {
				resolver = s.Tag
				break
			}
		}
	}
	return setDefaultDomainResolver(cfg, resolver)
}

// isSynthResolver reports whether the named server tag is a fakeip/hosts server
// (which synthesize answers and can't back default_domain_resolver).
func isSynthResolver(d apitypes.DNSConfig, tag string) bool {
	for _, s := range d.Servers {
		if s.Tag == tag {
			return s.Type == "fakeip" || s.Type == "hosts"
		}
	}
	return false
}

// ensureStoreFakeIP flips experimental.cache_file.store_fakeip on so fakeip
// address allocations survive rebuilds/restarts.
func ensureStoreFakeIP(cfg map[string]json.RawMessage, dataDir string) error {
	var exp map[string]json.RawMessage
	if raw, ok := cfg["experimental"]; ok {
		if err := json.Unmarshal(raw, &exp); err != nil {
			return err
		}
	} else {
		exp = map[string]json.RawMessage{}
	}
	var cf map[string]any
	if raw, ok := exp["cache_file"]; ok {
		if err := json.Unmarshal(raw, &cf); err != nil {
			return err
		}
	} else {
		cf = map[string]any{"enabled": true, "path": filepath.Join(dataDir, "cache.db")}
	}
	cf["store_fakeip"] = true
	ncf, err := json.Marshal(cf)
	if err != nil {
		return err
	}
	exp["cache_file"] = ncf
	newExp, err := json.Marshal(exp)
	if err != nil {
		return err
	}
	cfg["experimental"] = newExp
	return nil
}

func setDefaultDomainResolver(cfg map[string]json.RawMessage, server string) error {
	if server == "" {
		return nil
	}
	var route map[string]json.RawMessage
	if raw, ok := cfg["route"]; ok {
		if err := json.Unmarshal(raw, &route); err != nil {
			return err
		}
	} else {
		route = map[string]json.RawMessage{}
	}
	route["default_domain_resolver"], _ = json.Marshal(server)
	nr, err := json.Marshal(route)
	if err != nil {
		return err
	}
	cfg["route"] = nr
	return nil
}
