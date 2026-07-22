// Package gateway boots and owns the embedded sing-box instance (the data
// plane), attaches our detection tracker, and hot-reloads a rebuilt config when
// the applied subscription nodes or the egress whitelist change.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// ProxyGroupTag is the outbound group whose members we swap when applying a
// subscription. Whitelisted domains egress through it.
const ProxyGroupTag = "proxy"

// Operating modes: how the gateway captures traffic.
const (
	ModeManual = "manual" // mixed inbound only; apps point at 127.0.0.1:17070
	ModeSystem = "system" // mixed inbound + set the OS system proxy to it
	ModeTUN    = "tun"    // tun inbound + auto_route: capture ALL traffic (needs root)
)

// Modes lists the selectable operating modes.
var Modes = []string{ModeManual, ModeSystem, ModeTUN}

func validMode(m string) bool {
	for _, v := range Modes {
		if v == m {
			return true
		}
	}
	return false
}

// Manager owns the running box and rebuilds it in place when policy changes.
type Manager struct {
	configPath  string
	logger      log.Logger
	engine      *detect.Engine
	clashSecret string

	rebuildMu sync.Mutex // serializes rebuilds

	mu       sync.Mutex
	instance *box.Box
	nodes    []apitypes.Node
	wl       whitelist.Rules
	mode     string
	rulesets ruleset.Sets
}

// NewManager returns a manager seeded with the initial whitelist, the detection
// engine, and the Clash API secret to inject into the config.
func NewManager(configPath string, wl whitelist.Rules, engine *detect.Engine, clashSecret string) *Manager {
	return &Manager{configPath: configPath, logger: log.StdLogger(), wl: wl, engine: engine, clashSecret: clashSecret, mode: ModeManual}
}

// SetInitialMode sets the mode used by the first Start() (before the box runs).
func (m *Manager) SetInitialMode(mode string) {
	if validMode(mode) {
		m.mu.Lock()
		m.mode = mode
		m.mu.Unlock()
	}
}

// Mode returns the current operating mode.
func (m *Manager) Mode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// SetMode switches the capture mode and hot-reloads. If the new mode fails to
// start (e.g. TUN without root), it reverts to the previous mode so the gateway
// stays up.
func (m *Manager) SetMode(mode string) error {
	if !validMode(mode) {
		return fmt.Errorf("invalid mode %q (want one of %v)", mode, Modes)
	}
	m.mu.Lock()
	prev := m.mode
	if prev == mode {
		m.mu.Unlock()
		return nil
	}
	m.mode = mode
	m.mu.Unlock()

	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.mode = prev
		m.mu.Unlock()
		_ = m.rebuild() // best-effort restore of the working mode
		return fmt.Errorf("switch to %s failed (reverted to %s): %w", mode, prev, err)
	}
	m.logger.Info("gateway mode -> ", mode)
	return nil
}

// Start builds and starts the box from the base config + current policy.
func (m *Manager) Start() error { return m.rebuild() }

// Close stops the running box.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.instance == nil {
		return nil
	}
	return m.instance.Close()
}

// Apply sets the subscription nodes and hot-reloads (empty resets the proxy
// group to direct-only).
func (m *Manager) Apply(nodes []apitypes.Node) error {
	m.mu.Lock()
	m.nodes = nodes
	m.mu.Unlock()
	return m.rebuild()
}

// SetWhitelist sets the egress allow-list and hot-reloads. On rebuild failure
// (e.g. a malformed entry) it reverts to the previous list so the gateway stays
// up rather than going down with a bad config.
func (m *Manager) SetWhitelist(wl whitelist.Rules) error {
	m.mu.Lock()
	prev := m.wl
	m.wl = wl
	m.mu.Unlock()
	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.wl = prev
		m.mu.Unlock()
		_ = m.rebuild() // best-effort restore
		return fmt.Errorf("apply whitelist failed (reverted): %w", err)
	}
	return nil
}

// SetInitialRuleSets sets the imported rule sets used by the first Start().
func (m *Manager) SetInitialRuleSets(sets ruleset.Sets) {
	m.mu.Lock()
	m.rulesets = sets
	m.mu.Unlock()
}

// SetRuleSets sets the imported rule sets and hot-reloads.
func (m *Manager) SetRuleSets(sets ruleset.Sets) error {
	m.mu.Lock()
	m.rulesets = sets
	m.mu.Unlock()
	return m.rebuild()
}

// ApplyProfile atomically sets nodes + whitelist + rule sets + (optionally) mode
// and rebuilds ONCE, so a one-click profile switch is a single reload rather
// than four. mode=="" keeps the current mode.
func (m *Manager) ApplyProfile(nodes []apitypes.Node, wl whitelist.Rules, sets ruleset.Sets, mode string) error {
	m.mu.Lock()
	prevNodes, prevWL, prevSets, prevMode := m.nodes, m.wl, m.rulesets, m.mode
	m.nodes = nodes
	m.wl = wl
	m.rulesets = sets
	if mode != "" && validMode(mode) {
		m.mode = mode
	}
	m.mu.Unlock()

	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.nodes, m.wl, m.rulesets, m.mode = prevNodes, prevWL, prevSets, prevMode
		m.mu.Unlock()
		_ = m.rebuild() // best-effort restore of the working policy
		return fmt.Errorf("apply profile failed (reverted): %w", err)
	}
	return nil
}

func (m *Manager) rebuild() error {
	m.rebuildMu.Lock()
	defer m.rebuildMu.Unlock()

	m.mu.Lock()
	nodes, wl, mode, sets := m.nodes, m.wl, m.mode, m.rulesets
	m.mu.Unlock()

	base, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}
	merged, err := buildMergedConfig(base, nodes, wl, mode, sets, m.clashSecret)
	if err != nil {
		return fmt.Errorf("build config: %w", err)
	}
	newInst, err := m.buildBox(merged)
	if err != nil {
		return fmt.Errorf("build box: %w", err)
	}

	// Free listeners before starting the new instance (same ports): brief blip.
	m.mu.Lock()
	old := m.instance
	m.mu.Unlock()
	if old != nil {
		old.Close()
	}
	if err := newInst.Start(); err != nil {
		return fmt.Errorf("start box: %w", err)
	}
	m.mu.Lock()
	m.instance = newInst
	m.mu.Unlock()
	m.logger.Info("gateway reloaded (", len(nodes), " node(s), ", len(wl.Domains), " domain(s), ", len(wl.IPs), " ip(s))")
	return nil
}

func (m *Manager) buildBox(configBytes []byte) (*box.Box, error) {
	ctx := service.ContextWith(context.Background(), deprecated.NewStderrManager(m.logger))
	ctx = include.Context(ctx)

	options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, configBytes)
	if err != nil {
		return nil, err
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return nil, err
	}
	if os.Getenv("TP_NO_DETECTOR") == "" {
		instance.Router().AppendTracker(newDetector(m.engine))
	}
	return instance, nil
}

// buildMergedConfig injects (a) subscription node outbounds + the `proxy` group
// and (b) whitelist allow rules into the route, at the JSON level so sing-box's
// own parser validates the result.
func buildMergedConfig(base []byte, nodes []apitypes.Node, wl whitelist.Rules, mode string, sets ruleset.Sets, clashSecret string) ([]byte, error) {
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(base, &cfg); err != nil {
		return nil, err
	}
	if err := injectOutbounds(cfg, nodes); err != nil {
		return nil, err
	}
	if err := applyMode(cfg, mode); err != nil {
		return nil, err
	}
	if err := injectWhitelist(cfg, wl); err != nil {
		return nil, err
	}
	// Must run AFTER injectWhitelist: it anchors on the network-matcher catch-all
	// reject, which is the only reject present at whitelist time.
	if err := injectRuleSets(cfg, sets); err != nil {
		return nil, err
	}
	if err := injectClashSecret(cfg, clashSecret); err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
}

// injectRuleSets appends enabled rule_set descriptors to route.rule_set and
// weaves their match rules into route.rules preserving default-deny order:
//   sniff -> hijack-dns -> [block sets: reject] -> whitelist allows ->
//   [allow sets: route] -> reject catch-all
func injectRuleSets(cfg map[string]json.RawMessage, sets ruleset.Sets) error {
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
			desc["url"] = rs.URL
			desc["download_detour"] = rs.DownloadDetour // always "direct" under default-deny
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

	// (2) weave rules. Anchor on the catch-all reject (the reject carrying a
	// network matcher). prelude = leading sniff/hijack-dns; middle = whitelist
	// allow rules between prelude and the catch-all; tail = catch-all onward.
	var rules []json.RawMessage
	if raw, ok := route["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return err
		}
	}
	catchIdx := len(rules)
	for i, r := range rules {
		var m struct {
			Network json.RawMessage `json:"network"`
		}
		_ = json.Unmarshal(r, &m)
		if len(m.Network) > 0 { // default-deny catch-all (reject or route->block)
			catchIdx = i
			break
		}
	}
	preludeEnd := 0
	for preludeEnd < catchIdx {
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
	prelude := rules[:preludeEnd]
	middle := rules[preludeEnd:catchIdx]
	tail := rules[catchIdx:]

	var blockTags, directTags, proxyTags []string
	for _, rs := range enabled {
		switch rs.Role {
		case apitypes.RuleRoleBlock:
			blockTags = append(blockTags, rs.Tag)
		case apitypes.RuleRoleAllowDirect:
			directTags = append(directTags, rs.Tag)
		case apitypes.RuleRoleAllowProxy:
			proxyTags = append(proxyTags, rs.Tag)
		}
	}
	var blockRules, allowRules []json.RawMessage
	if len(blockTags) > 0 {
		r, _ := json.Marshal(map[string]any{"rule_set": blockTags, "action": "reject"})
		blockRules = append(blockRules, r)
	}
	if len(directTags) > 0 {
		r, _ := json.Marshal(map[string]any{"rule_set": directTags, "action": "route", "outbound": "direct"})
		allowRules = append(allowRules, r)
	}
	if len(proxyTags) > 0 {
		r, _ := json.Marshal(map[string]any{"rule_set": proxyTags, "action": "route", "outbound": ProxyGroupTag})
		allowRules = append(allowRules, r)
	}

	merged := make([]json.RawMessage, 0, len(rules)+len(blockRules)+len(allowRules))
	merged = append(merged, prelude...)
	merged = append(merged, blockRules...)
	merged = append(merged, middle...)
	merged = append(merged, allowRules...)
	merged = append(merged, tail...)
	nr, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	route["rules"] = nr
	nroute, err := json.Marshal(route)
	if err != nil {
		return err
	}
	cfg["route"] = nroute

	// Remote rule_set needs a cache so the frequent rebuilds don't re-download
	// (and a cached copy survives a blocked URL). Ensure cache_file is on.
	return ensureCacheFile(cfg)
}

// ensureCacheFile turns on experimental.cache_file (persists downloaded .srs +
// selected outbound across rebuilds/restarts).
func ensureCacheFile(cfg map[string]json.RawMessage) error {
	var exp map[string]json.RawMessage
	if raw, ok := cfg["experimental"]; ok {
		if err := json.Unmarshal(raw, &exp); err != nil {
			return err
		}
	} else {
		exp = map[string]json.RawMessage{}
	}
	if _, ok := exp["cache_file"]; !ok {
		cf, _ := json.Marshal(map[string]any{"enabled": true, "path": "data/cache.db"})
		exp["cache_file"] = cf
	}
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
func applyMode(cfg map[string]json.RawMessage, mode string) error {
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

	var ins []map[string]any
	switch mode {
	case ModeSystem:
		mixed["set_system_proxy"] = true
		ins = []map[string]any{mixed}
	case ModeTUN:
		tunIn := map[string]any{
			"type": "tun", "tag": "tun-in",
			"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route":   true,
			"strict_route": true,
			"stack":        "gvisor",
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
// omits: a local DNS server, a hijack-dns route rule (before the reject), and
// auto_detect_interface.
func ensureTunExtras(cfg map[string]json.RawMessage) error {
	if _, ok := cfg["dns"]; !ok {
		dns, _ := json.Marshal(map[string]any{
			"servers": []map[string]any{{"type": "udp", "tag": "dns-local", "server": "223.5.5.5"}},
		})
		cfg["dns"] = dns
	}
	routeRaw, ok := cfg["route"]
	if !ok {
		return nil
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
		at := sniffIdx + 1 // after sniff (or at 0 if none)
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

func injectOutbounds(cfg map[string]json.RawMessage, nodes []apitypes.Node) error {
	var outs []json.RawMessage
	if raw, ok := cfg["outbounds"]; ok {
		if err := json.Unmarshal(raw, &outs); err != nil {
			return err
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
		tag := uniq(stringOr(ob["tag"], n.Tag))
		ob["tag"] = tag
		raw, err := json.Marshal(ob)
		if err != nil {
			continue
		}
		kept = append(kept, raw)
		tags = append(tags, tag)
	}

	var group map[string]any
	if len(tags) == 0 {
		group = map[string]any{"type": "selector", "tag": ProxyGroupTag, "outbounds": []string{"direct"}}
	} else {
		group = map[string]any{
			"type": "urltest", "tag": ProxyGroupTag, "outbounds": tags,
			"url": "https://www.gstatic.com/generate_204", "interval": "3m",
		}
	}
	groupRaw, err := json.Marshal(group)
	if err != nil {
		return err
	}
	kept = append(kept, groupRaw)

	newOuts, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	cfg["outbounds"] = newOuts
	return nil
}

// injectWhitelist inserts allow rules (domains -> proxy, ips -> direct) right
// before the catch-all reject rule in route.rules.
func injectWhitelist(cfg map[string]json.RawMessage, wl whitelist.Rules) error {
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

	var allow []json.RawMessage
	// Process allow-list (opt-in): reject any connection whose process is NOT in
	// the list. Placed first so unknown binaries are dropped before the
	// destination allows even consider them. Entries with a path separator match
	// process_path; others match process_name.
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
		allow = append(allow, r)
	}
	// Device (source) allow-list: reject connections whose source IP is not a
	// known device. For gateway/router deployments (source_ip_cidr).
	if len(wl.Devices) > 0 {
		r, _ := json.Marshal(map[string]any{"source_ip_cidr": wl.Devices, "invert": true, "action": "reject"})
		allow = append(allow, r)
	}
	if len(wl.Domains) > 0 {
		r, _ := json.Marshal(map[string]any{"domain_suffix": wl.Domains, "action": "route", "outbound": ProxyGroupTag})
		allow = append(allow, r)
	}
	if len(wl.IPs) > 0 {
		r, _ := json.Marshal(map[string]any{"ip_cidr": wl.IPs, "action": "route", "outbound": "direct"})
		allow = append(allow, r)
	}

	// insert before the default-deny catch-all (the rule carrying the bare
	// network matcher — reject, or route->block outbound).
	catchIdx := len(rules)
	for i, raw := range rules {
		var meta struct {
			Network json.RawMessage `json:"network"`
		}
		_ = json.Unmarshal(raw, &meta)
		if len(meta.Network) > 0 {
			catchIdx = i
			break
		}
	}
	merged := make([]json.RawMessage, 0, len(rules)+len(allow))
	merged = append(merged, rules[:catchIdx]...)
	merged = append(merged, allow...)
	merged = append(merged, rules[catchIdx:]...)

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

func stringOr(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}
