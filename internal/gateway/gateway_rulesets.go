// Imported rule_set injection: descriptors + deny-role reject rules (L1);
// permit/route roles are consumed later by injectAllow (see gateway_allow.go).
package gateway

import (
	"encoding/json"
	"path/filepath"

	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// injectRuleSets registers enabled rule_set descriptors in route.rule_set and
// emits block-role rejects into the L1 security floor (right after the prelude).
// Allow-role rule_sets are NOT routed here — injectAllow (L3/L4) owns both the
// allow decision and the egress choice for them.
func injectRuleSets(cfg map[string]json.RawMessage, sets ruleset.Sets, dataDir string, hasExit bool) error {
	var enabled []apitypes.RuleSet
	for _, rs := range sets.Sets {
		if rs.Enabled && rs.Tag != "" {
			enabled = append(enabled, rs)
		}
	}
	if len(enabled) == 0 {
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

	// (1) route.rule_set[] descriptors, dedup by tag (idempotent re-inject).
	var descriptors []json.RawMessage
	if raw, ok := route["rule_set"]; ok {
		if err := json.Unmarshal(raw, &descriptors); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, d := range descriptors {
		var m struct {
			Tag string `json:"tag"`
		}
		_ = json.Unmarshal(d, &m)
		if m.Tag != "" {
			seen[m.Tag] = true
		}
	}
	for _, rs := range enabled {
		if seen[rs.Tag] {
			continue
		}
		desc := map[string]any{"type": rs.Type, "tag": rs.Tag, "format": rs.Format}
		if rs.Type == "local" {
			desc["path"] = rs.Path
		} else {
			// The .srs fetch dials download_detour directly (it bypasses route.rules),
			// so under default-deny it isn't the whitelist that blocks it — a direct
			// dial to e.g. raw.githubusercontent.com is what fails behind the GFW.
			// When an exit is configured, download THROUGH the proxy group so the
			// fetch crosses the GFW; otherwise fall back to direct.
			detour := rs.DownloadDetour
			if detour == "" {
				detour = "direct"
			}
			if detour == "direct" && hasExit {
				detour = ProxyGroupTag
			}
			desc["url"] = rs.URL
			// http_client replaces both deprecations sing-box 1.14 warns about and
			// 1.16 removes: the legacy `download_detour` option, and relying on the
			// implicit default HTTP client. Pinning domain_resolver here also keeps
			// the .srs fetch off the exit-node resolver, same rule as every other
			// direct dial (see injectDirectDNS).
			desc["http_client"] = map[string]any{
				"detour":          detour,
				"domain_resolver": directResolverTag,
			}
			desc["update_interval"] = rs.UpdateInterval
		}
		raw, err := json.Marshal(desc)
		if err != nil {
			return err
		}
		descriptors = append(descriptors, raw)
		seen[rs.Tag] = true
	}
	nrs, err := json.Marshal(descriptors)
	if err != nil {
		return err
	}
	route["rule_set"] = nrs

	// (2) deny-role rule_sets -> reject (L1 floor), inserted right after the
	// prelude so they sit above the ACL gate. Permit/route roles are handled
	// by injectAllow.
	var blockTags []string
	for _, rs := range enabled {
		if apitypes.RuleRoleIsDeny(rs.Role) {
			blockTags = append(blockTags, rs.Tag)
		}
	}
	if len(blockTags) > 0 {
		var rules []json.RawMessage
		if raw, ok := route["rules"]; ok {
			if err := json.Unmarshal(raw, &rules); err != nil {
				return err
			}
		}
		at := preludeLen(rules)
		blockRule, _ := json.Marshal(map[string]any{"rule_set": blockTags, "action": "reject"})
		merged := make([]json.RawMessage, 0, len(rules)+1)
		merged = append(merged, rules[:at]...)
		merged = append(merged, blockRule)
		merged = append(merged, rules[at:]...)
		nr, err := json.Marshal(merged)
		if err != nil {
			return err
		}
		route["rules"] = nr
	}
	nroute, err := json.Marshal(route)
	if err != nil {
		return err
	}
	cfg["route"] = nroute

	// Remote rule_set needs a cache so the frequent rebuilds don't re-download
	// (and a cached copy survives a blocked URL). Ensure cache_file is on.
	return ensureCacheFile(cfg, dataDir)
}

// ensureCacheFile turns on experimental.cache_file (persists downloaded .srs +
// selected outbound across rebuilds/restarts).
func ensureCacheFile(cfg map[string]json.RawMessage, dataDir string) error {
	var exp map[string]json.RawMessage
	if raw, ok := cfg["experimental"]; ok {
		if err := json.Unmarshal(raw, &exp); err != nil {
			return err
		}
	} else {
		exp = map[string]json.RawMessage{}
	}
	if _, ok := exp["cache_file"]; !ok {
		cf, _ := json.Marshal(map[string]any{"enabled": true, "path": filepath.Join(dataDir, "cache.db")})
		exp["cache_file"] = cf
	}
	newExp, err := json.Marshal(exp)
	if err != nil {
		return err
	}
	cfg["experimental"] = newExp
	return nil
}
