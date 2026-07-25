// Outbound/proxy-group topology: node tags, endpoint injection, Auto/Overseas/
// per-country/user groups, and the selector the whitelist gate points at.
package gateway

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// injectEndpoints appends enabled WireGuard/Tailscale exits to endpoints[] and
// returns their tags (to be added to the proxy group). WireGuard peers keep the
// pasted allowed_ips; Tailscale gets a per-tag state dir under data/.
func injectEndpoints(cfg map[string]json.RawMessage, list []apitypes.Endpoint, dataDir string) ([]string, error) {
	var eps []json.RawMessage
	if raw, ok := cfg["endpoints"]; ok {
		if err := json.Unmarshal(raw, &eps); err != nil {
			return nil, err
		}
	}
	var tags []string
	for _, e := range list {
		if !e.Enabled || e.Tag == "" {
			continue
		}
		var m map[string]any
		switch e.Type {
		case "wireguard":
			host, portStr, err := net.SplitHostPort(e.PeerEndpoint)
			if err != nil {
				return nil, fmt.Errorf("endpoint %q: bad peer_endpoint: %w", e.Tag, err)
			}
			port, _ := strconv.Atoi(portStr)
			peer := map[string]any{"address": host, "port": port, "public_key": e.PeerPublicKey, "allowed_ips": e.AllowedIPs}
			if e.PeerPreSharedKey != "" {
				peer["pre_shared_key"] = e.PeerPreSharedKey
			}
			if e.PersistentKeepalive > 0 {
				peer["persistent_keepalive_interval"] = e.PersistentKeepalive
			}
			m = map[string]any{"type": "wireguard", "tag": e.Tag, "address": e.Address, "private_key": e.PrivateKey, "peers": []any{peer}}
			if e.MTU > 0 {
				m["mtu"] = e.MTU
			}
		case "tailscale":
			m = map[string]any{"type": "tailscale", "tag": e.Tag, "auth_key": e.AuthKey, "state_directory": filepath.Join(dataDir, "ts-"+e.Tag)}
			if e.Hostname != "" {
				m["hostname"] = e.Hostname
			}
			if e.ExitNode != "" {
				m["exit_node"] = e.ExitNode
			}
			if e.AcceptRoutes {
				m["accept_routes"] = true
			}
		default:
			continue
		}
		raw, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		eps = append(eps, raw)
		tags = append(tags, e.Tag)
	}
	if len(eps) > 0 {
		nb, err := json.Marshal(eps)
		if err != nil {
			return nil, err
		}
		cfg["endpoints"] = nb
	}
	return tags, nil
}

// memberTags computes the proxy group's member tags for the given nodes +
// extra (endpoint) tags, applying the same empty->"node" fallback and -2/-3
// de-duplication that injectOutbounds uses. It is the single source of truth
// for node tag naming (injectOutbounds zips its result back onto the outbounds)
// and lets EffectiveRules tell whether a custom `node` rule points at a live
// outbound. Node order in == tag order out.
func memberTags(nodes []apitypes.Node, extraTags []string) []string {
	used := map[string]bool{}
	uniq := func(t string) string {
		if t == "" {
			t = "node"
		}
		base := t
		for i := 2; used[t]; i++ {
			t = fmt.Sprintf("%s-%d", base, i)
		}
		used[t] = true
		return t
	}
	var tags []string
	for _, n := range nodes {
		if len(n.Outbound) == 0 {
			continue
		}
		var ob map[string]any
		if err := json.Unmarshal(n.Outbound, &ob); err != nil {
			continue
		}
		tags = append(tags, uniq(stringOr(ob["tag"], n.Tag)))
	}
	tags = append(tags, extraTags...)
	return tags
}

// groupMembers resolves a user group's member tags from the full node/endpoint
// tag pool, per its filter (country / regex / manual). Order follows the pool.
func groupMembers(g proxygroups.Group, tags []string) []string {
	var m []string
	switch g.Filter {
	case proxygroups.FilterCountry:
		for _, t := range tags {
			if proxygroups.Country(t) == g.Value {
				m = append(m, t)
			}
		}
	case proxygroups.FilterRegex:
		re, err := regexp.Compile(g.Value)
		if err != nil {
			return nil
		}
		for _, t := range tags {
			if re.MatchString(t) {
				m = append(m, t)
			}
		}
	case proxygroups.FilterManual:
		set := map[string]bool{}
		for _, t := range tags {
			set[t] = true
		}
		for _, n := range g.Nodes {
			if set[n] {
				m = append(m, n)
			}
		}
	}
	return m
}

// excludeSet builds a lookup of excluded ISO country codes (already normalized
// upper-case by the store) for the shared Overseas group.
func excludeSet(codes []string) map[string]bool {
	m := make(map[string]bool, len(codes))
	for _, c := range codes {
		if c != "" {
			m[c] = true
		}
	}
	return m
}

// loopbackTags returns the set of member tags whose outbound server is
// loopback/localhost. Mirrors the classification injectOutbounds feeds into
// buildProxyGroups so EffectiveRules stays in sync.
func loopbackTags(nodes []apitypes.Node) map[string]bool {
	out := map[string]bool{}
	tags := memberTags(nodes, nil)
	ti := 0
	for _, n := range nodes {
		if len(n.Outbound) == 0 {
			continue
		}
		var ob map[string]any
		if err := json.Unmarshal(n.Outbound, &ob); err != nil {
			continue
		}
		tag := tags[ti]
		ti++
		if isLoopbackHost(stringOr(ob["server"], n.Server)) {
			out[tag] = true
		}
	}
	return out
}

// isLoopbackHost reports whether a node server address targets the local
// machine (127.0.0.0/8, ::1, localhost). Those are fine as manual exits
// (e.g. Cloudflare WARP's local SOCKS) but must not sit in Auto/urltest: when
// the local agent is down, urltest still latches onto them and all proxied
// traffic (Google, etc.) blackholes.
func isLoopbackHost(server string) bool {
	host := strings.TrimSpace(server)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// buildProxyGroups turns the member pool (node + endpoint tags) into sing-box
// group outbounds and the top-level `proxy` selector. It returns the outbound
// JSON to append AND the group tags (Auto + per-country + user groups, NOT the
// proxy selector) — those extend the valid `node`-action targets. Layering:
//   - Auto: urltest over non-loopback members (the default the proxy selector
//     points at). Loopback-only pools fall back to the full tag list so a
//     WARP-only setup still works.
//   - Local: selector over loopback members (when any exist alongside remotes).
//   - per-country urltest groups (when AutoCountry and ≥1 country is detected).
//   - user groups (select|urltest) by country/regex/manual filter.
//   - proxy: selector over [Auto, Local?, country…, user…], default = Auto.
//
// Empty pool => proxy is selector[direct] and there are no groups.
// It is pure (no cfg mutation) so EffectiveRules can reuse it for the member set.
// loopback marks tags whose outbound server is localhost; nil/empty is fine.
func buildProxyGroups(tags []string, loopback map[string]bool, pg proxygroups.Config) (outs []json.RawMessage, groupTags []string) {
	if len(tags) == 0 {
		sel, _ := json.Marshal(map[string]any{"type": "selector", "tag": ProxyGroupTag, "outbounds": []string{"direct"}})
		return []json.RawMessage{sel}, nil
	}
	used := map[string]bool{"direct": true, "blocked": true, ProxyGroupTag: true}
	for _, t := range tags {
		used[t] = true
	}
	uniq := func(name string) string {
		if name == "" {
			name = "group"
		}
		base, t := name, name
		for i := 2; used[t]; i++ {
			t = fmt.Sprintf("%s-%d", base, i)
		}
		used[t] = true
		return t
	}
	add := func(typ, tag string, members []string) {
		g := map[string]any{"type": typ, "tag": tag, "outbounds": members}
		if typ == "urltest" {
			// Failover is primarily driven by dial/IO failures (patched urltest
			// retries other members immediately). The periodic probe is a backup
			// only — keep it short so a quietly-dead node cannot stick for minutes.
			g["url"] = "https://www.gstatic.com/generate_204"
			g["interval"] = "30s"
			g["idle_timeout"] = "30m"
			g["interrupt_exist_connections"] = true
		}
		b, _ := json.Marshal(g)
		outs = append(outs, b)
		groupTags = append(groupTags, tag)
	}

	var remote, local []string
	for _, t := range tags {
		if loopback[t] {
			local = append(local, t)
		} else {
			remote = append(remote, t)
		}
	}
	autoMembers := remote
	if len(autoMembers) == 0 {
		autoMembers = tags // WARP-only / all-loopback: Auto must still have members
	}

	autoTag := uniq("Auto")
	add("urltest", autoTag, autoMembers)
	if len(local) > 0 && len(remote) > 0 {
		add("selector", uniq("Local"), local)
	}

	// Shared "Overseas" group: urltest over every non-loopback node whose country
	// is NOT excluded (default HK/MO/CN). Built ONLY when the exclusion actually
	// removes ≥1 node — if nothing is excluded, Auto is already a safe superset
	// and any rule targeting Overseas self-heals back to Auto. This gives
	// geofenced services (Anthropic/OpenAI/Cursor) failover across allowed
	// regions that can never land on a blocked one.
	if ex := excludeSet(pg.ExcludeCountries); len(ex) > 0 {
		var allowed []string
		for _, t := range remote {
			if !ex[proxygroups.Country(t)] {
				allowed = append(allowed, t)
			}
		}
		if len(allowed) > 0 && len(allowed) < len(remote) {
			add("urltest", uniq(proxygroups.OverseasGroupTag), allowed)
		}
	}

	if pg.AutoCountry {
		buckets := map[string][]string{}
		var order []string
		real := 0
		for _, t := range remote {
			c := proxygroups.Country(t)
			if c == "" {
				c = "Other"
			}
			if _, ok := buckets[c]; !ok {
				order = append(order, c)
				if c != "Other" {
					real++
				}
			}
			buckets[c] = append(buckets[c], t)
		}
		if real > 0 { // skip country grouping when nothing is identifiable (== Auto)
			for _, c := range order {
				label := "Other"
				if c != "Other" {
					label = proxygroups.CountryName(c)
				}
				add("urltest", uniq(label), buckets[c])
			}
		}
	}

	for _, ug := range pg.Groups {
		members := groupMembers(ug, tags)
		if len(members) == 0 {
			continue // an empty group is invalid in sing-box and useless anyway
		}
		typ := "urltest"
		if ug.Type == proxygroups.TypeSelect {
			typ = "selector"
		}
		add(typ, uniq(ug.Name), members)
	}

	sel, _ := json.Marshal(map[string]any{"type": "selector", "tag": ProxyGroupTag, "outbounds": groupTags, "default": autoTag})
	outs = append(outs, sel)
	return outs, groupTags
}

// injectOutbounds rewrites outbounds from the subscription nodes + the proxy
// group tree, and returns the valid `node`-action targets: node + endpoint
// outbound tags PLUS the group tags (Auto / country / user groups), and the
// set of tags whose server is loopback (for applyInvariants).
func injectOutbounds(cfg map[string]json.RawMessage, nodes []apitypes.Node, extraTags []string, pg proxygroups.Config) ([]string, map[string]bool, error) {
	var outs []json.RawMessage
	if raw, ok := cfg["outbounds"]; ok {
		if err := json.Unmarshal(raw, &outs); err != nil {
			return nil, nil, err
		}
	}
	kept := outs[:0:0]
	for _, raw := range outs {
		var meta struct {
			Tag string `json:"tag"`
		}
		_ = json.Unmarshal(raw, &meta)
		if meta.Tag == ProxyGroupTag {
			continue
		}
		kept = append(kept, raw)
	}

	// memberTags is the single source of truth for node tag naming; zip it back
	// onto the (identically-skipped) nodes so outbound tags match the member set.
	nodeTags := memberTags(nodes, nil)
	var tags []string
	loopback := map[string]bool{}
	ti := 0
	for _, n := range nodes {
		if len(n.Outbound) == 0 {
			continue
		}
		var ob map[string]any
		if err := json.Unmarshal(n.Outbound, &ob); err != nil {
			continue
		}
		tag := nodeTags[ti]
		ti++
		ob["tag"] = tag
		raw, err := json.Marshal(ob)
		if err != nil {
			continue
		}
		kept = append(kept, raw)
		tags = append(tags, tag)
		if isLoopbackHost(stringOr(ob["server"], n.Server)) {
			loopback[tag] = true
		}
	}
	// WireGuard/Tailscale endpoint tags (defined in endpoints[]) are valid group
	// members — append so groups can urltest across nodes + exits.
	tags = append(tags, extraTags...)

	groupOuts, groupTags := buildProxyGroups(tags, loopback, pg)
	kept = append(kept, groupOuts...)

	newOuts, err := json.Marshal(kept)
	if err != nil {
		return nil, nil, err
	}
	cfg["outbounds"] = newOuts
	// Valid node-action targets = individual nodes/endpoints ∪ the group tags.
	return append(append([]string(nil), tags...), groupTags...), loopback, nil
}
