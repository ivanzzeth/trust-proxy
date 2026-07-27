// Imported rule_set injection: descriptors + deny-role reject rules (L1);
// permit/route roles are consumed later by injectAllow (see gateway_allow.go).
package gateway

import (
	"encoding/json"
	"path/filepath"

	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// ruleSetHTTPClientTag names the declared HTTP client that remote rule sets are
// fetched with. See the comment at its use below for why it has to be a declared
// tag rather than an inline object.
const ruleSetHTTPClientTag = "rule-set-fetch"

// declareRuleSetHTTPClient adds the http_clients entry that ruleSetHTTPClientTag
// refers to, unless the operator's own config already declares that tag.
//
// No detour: dial directly. No other options either — every field would have to
// be justified, and the tag alone is enough to keep the entry non-empty.
func declareRuleSetHTTPClient(cfg map[string]json.RawMessage) error {
	var clients []map[string]any
	if raw, ok := cfg["http_clients"]; ok {
		if err := json.Unmarshal(raw, &clients); err != nil {
			return err
		}
		for _, c := range clients {
			if tag, _ := c["tag"].(string); tag == ruleSetHTTPClientTag {
				return nil // theirs wins; a duplicate tag is a hard parse error
			}
		}
	}
	clients = append(clients, map[string]any{"tag": ruleSetHTTPClientTag})
	raw, err := json.Marshal(clients)
	if err != nil {
		return err
	}
	cfg["http_clients"] = raw
	return nil
}

// injectRuleSets registers enabled rule_set descriptors in route.rule_set and
// emits block-role rejects into the L1 security floor (right after the prelude).
// Allow-role rule_sets are NOT routed here — injectAllow (L3/L4) owns both the
// allow decision and the egress choice for them.
func injectRuleSets(cfg map[string]json.RawMessage, sets ruleset.Sets, dataDir string) error {
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
	needsSharedClient := false
	for _, rs := range enabled {
		if seen[rs.Tag] {
			continue
		}
		desc := map[string]any{"type": rs.Type, "tag": rs.Tag, "format": rs.Format}
		if rs.Type == "local" {
			desc["path"] = rs.Path
		} else {
			desc["url"] = rs.URL
			// The fetch does NOT traverse route.rules — it dials whatever transport
			// this descriptor names, so no allow-list, gate or exemption is involved.
			// That is the whole reason this line has been wrong three times:
			//
			//  1. `download_detour: "direct"` worked, but 1.16 removes the option.
			//  2. `http_client: {"detour": "direct"}` is refused outright — "detour to
			//     an empty direct outbound makes no sense".
			//  3. `http_client: {}` parses, starts on an existing install, and dials
			//     into `blocked` on a fresh one. Empty is load-bearing upstream:
			//     IsEmpty() (option/http.go:54) sends resolveTransport to
			//     DefaultTransport(), whose fallback sets DefaultOutbound (box.go:415)
			//     — and the default outbound is route.final (adapter/outbound/
			//     manager.go:303), which for us is `blocked`. Hence "operation not
			//     permitted", six times, on the first switch to Split.
			//
			// A *declared* client referenced by tag is none of those: the tag alone
			// makes it non-empty, and omitting detour means dial directly. It also
			// becomes the config's default HTTP client (httpclient.NewManager falls
			// back to clients[0]), which retires the implicit-default deprecation for
			// every other consumer too, not just rule sets.
			//
			// Direct, not through the proxy group, even when an exit exists. Routing
			// the fetch through the exit reads like an improvement (it crosses the
			// GFW) and is a startup hazard: a rule set that cannot be fetched on
			// *initial* load is fatal, so one dead node in an applied subscription
			// means the gateway does not come up at all — with the reason in a log
			// file. Reachability is handled where it belongs, by picking a mirror
			// that answers (ruleset.ResolveSources), and an operator who really
			// wants the proxy path can still say so per set via download_detour.
			if d := rs.DownloadDetour; d != "" && d != "direct" {
				desc["http_client"] = map[string]any{"detour": d}
			} else {
				desc["http_client"] = ruleSetHTTPClientTag
				needsSharedClient = true
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

	if needsSharedClient {
		if err := declareRuleSetHTTPClient(cfg); err != nil {
			return err
		}
	}

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
