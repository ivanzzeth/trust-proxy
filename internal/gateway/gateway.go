// Package gateway boots and owns the embedded sing-box instance (the data
// plane), attaches our detection tracker, and hot-reloads a rebuilt config when
// the applied subscription nodes or the egress whitelist change.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
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
	bl       blacklist.Rules
	mode     string
	rulesets ruleset.Sets
	dns       apitypes.DNSConfig
	inbound   apitypes.InboundAuth
	tun       apitypes.TUNConfig
	endpoints []apitypes.Endpoint
	mgmtPorts []int

	// mode dead-man's switch (remote-safety): a guarded mode switch auto-reverts
	// unless confirmed in time.
	guardMu     sync.Mutex
	revertTimer *time.Timer
	revertTo    string
	revertAt    time.Time
}

// SetInitialManagementPorts sets ports whose local responses always bypass
// default-deny (SSH, the API port) so a remote capture can't lock you out.
func (m *Manager) SetInitialManagementPorts(ports []int) {
	m.mu.Lock()
	m.mgmtPorts = ports
	m.mu.Unlock()
}

// SetInitialEndpoints sets WireGuard/Tailscale exits used by the first Start().
func (m *Manager) SetInitialEndpoints(eps []apitypes.Endpoint) {
	m.mu.Lock()
	m.endpoints = eps
	m.mu.Unlock()
}

// SetEndpoints sets the exit endpoints and hot-reloads (reverts on failure).
func (m *Manager) SetEndpoints(eps []apitypes.Endpoint) error {
	m.mu.Lock()
	prev := m.endpoints
	m.endpoints = eps
	m.mu.Unlock()
	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.endpoints = prev
		m.mu.Unlock()
		_ = m.rebuild()
		return fmt.Errorf("apply endpoints failed (reverted): %w", err)
	}
	return nil
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

// SetModeGuarded switches mode and arms a dead-man's switch: unless ConfirmMode
// is called within revertAfter, it reverts to the previous mode. This protects
// remote boxes — a TUN/system-proxy switch that severs your own access will
// auto-recover instead of bricking. Returns the previous mode (revert target).
func (m *Manager) SetModeGuarded(mode string, revertAfter time.Duration) (string, error) {
	m.mu.Lock()
	prev := m.mode
	m.mu.Unlock()
	if err := m.SetMode(mode); err != nil {
		return "", err
	}
	if prev == mode || revertAfter <= 0 {
		return prev, nil // no-op switch or no guard requested
	}
	m.guardMu.Lock()
	if m.revertTimer != nil {
		m.revertTimer.Stop()
	}
	m.revertTo = prev
	m.revertAt = m.nowUTC().Add(revertAfter)
	m.revertTimer = time.AfterFunc(revertAfter, func() {
		m.guardMu.Lock()
		to := m.revertTo
		armed := m.revertTimer != nil
		m.revertTimer = nil
		m.revertTo = ""
		m.revertAt = time.Time{}
		m.guardMu.Unlock()
		if armed && to != "" {
			m.logger.Warn("mode guard: not confirmed, reverting to ", to)
			_ = m.SetMode(to)
		}
	})
	m.guardMu.Unlock()
	return prev, nil
}

// ConfirmMode cancels a pending guarded revert (you confirmed you still have
// access).
func (m *Manager) ConfirmMode() {
	m.guardMu.Lock()
	if m.revertTimer != nil {
		m.revertTimer.Stop()
	}
	m.revertTimer = nil
	m.revertTo = ""
	m.revertAt = time.Time{}
	m.guardMu.Unlock()
}

// PendingRevert reports a pending guarded revert, if any.
func (m *Manager) PendingRevert() (to string, secondsLeft int, ok bool) {
	m.guardMu.Lock()
	defer m.guardMu.Unlock()
	if m.revertTimer == nil || m.revertTo == "" {
		return "", 0, false
	}
	left := int(time.Until(m.revertAt).Seconds())
	if left < 0 {
		left = 0
	}
	return m.revertTo, left, true
}

func (m *Manager) nowUTC() time.Time { return time.Now() }

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

// SetInitialBlacklist sets the egress deny-list used by the first Start()
// (before the box runs).
func (m *Manager) SetInitialBlacklist(bl blacklist.Rules) {
	m.mu.Lock()
	m.bl = bl
	m.mu.Unlock()
}

// SetBlacklist sets the egress deny-list and hot-reloads. On rebuild failure
// (e.g. a malformed entry) it reverts to the previous list so the gateway stays
// up rather than going down with a bad config.
func (m *Manager) SetBlacklist(bl blacklist.Rules) error {
	m.mu.Lock()
	prev := m.bl
	m.bl = bl
	m.mu.Unlock()
	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.bl = prev
		m.mu.Unlock()
		_ = m.rebuild() // best-effort restore
		return fmt.Errorf("apply blacklist failed (reverted): %w", err)
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

// SetInitialDNS sets the DNS config used by the first Start().
func (m *Manager) SetInitialDNS(d apitypes.DNSConfig) {
	m.mu.Lock()
	m.dns = d
	m.mu.Unlock()
}

// SetDNS sets the resolver policy and hot-reloads (reverts on failure).
func (m *Manager) SetDNS(d apitypes.DNSConfig) error {
	m.mu.Lock()
	prev := m.dns
	m.dns = d
	m.mu.Unlock()
	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.dns = prev
		m.mu.Unlock()
		_ = m.rebuild()
		return fmt.Errorf("apply DNS failed (reverted): %w", err)
	}
	return nil
}

// SetInitialInbound sets the mixed-inbound auth used by the first Start().
func (m *Manager) SetInitialInbound(a apitypes.InboundAuth) {
	m.mu.Lock()
	m.inbound = a
	m.mu.Unlock()
}

// SetInbound sets the mixed-inbound auth and hot-reloads (reverts on failure).
func (m *Manager) SetInbound(a apitypes.InboundAuth) error {
	m.mu.Lock()
	prev := m.inbound
	m.inbound = a
	m.mu.Unlock()
	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.inbound = prev
		m.mu.Unlock()
		_ = m.rebuild() // best-effort restore
		return fmt.Errorf("apply inbound auth failed (reverted): %w", err)
	}
	return nil
}

// SetInitialTUN sets the tun-inbound options used by the first Start().
func (m *Manager) SetInitialTUN(t apitypes.TUNConfig) {
	m.mu.Lock()
	m.tun = t
	m.mu.Unlock()
}

// SetTUN sets the tun-inbound options and hot-reloads (reverts on failure).
func (m *Manager) SetTUN(t apitypes.TUNConfig) error {
	m.mu.Lock()
	prev := m.tun
	m.tun = t
	m.mu.Unlock()
	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.tun = prev
		m.mu.Unlock()
		_ = m.rebuild() // best-effort restore
		return fmt.Errorf("apply TUN options failed (reverted): %w", err)
	}
	return nil
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
	nodes, wl, bl, mode, sets, dns, inbound, tun, eps, mgmt := m.nodes, m.wl, m.bl, m.mode, m.rulesets, m.dns, m.inbound, m.tun, m.endpoints, m.mgmtPorts
	m.mu.Unlock()

	base, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}
	merged, err := buildMergedConfig(base, nodes, wl, bl, mode, sets, dns, inbound, tun, eps, mgmt, m.clashSecret)
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
func buildMergedConfig(base []byte, nodes []apitypes.Node, wl whitelist.Rules, bl blacklist.Rules, mode string, sets ruleset.Sets, dns apitypes.DNSConfig, inbound apitypes.InboundAuth, tun apitypes.TUNConfig, endpoints []apitypes.Endpoint, mgmtPorts []int, clashSecret string) ([]byte, error) {
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(base, &cfg); err != nil {
		return nil, err
	}
	// WireGuard/Tailscale exits go in endpoints[]; their tags join the proxy group.
	epTags, err := injectEndpoints(cfg, endpoints)
	if err != nil {
		return nil, err
	}
	if err := injectOutbounds(cfg, nodes, epTags); err != nil {
		return nil, err
	}
	// Before applyMode: a configured dns block wins over TUN's default resolver.
	if err := injectDNS(cfg, dns); err != nil {
		return nil, err
	}
	if err := applyMode(cfg, mode, inbound, tun); err != nil {
		return nil, err
	}
	// Deny-list first: reject rules go right after the prelude, ABOVE the
	// whitelist allows, so a blacklisted target is dropped no matter what.
	if err := injectBlacklist(cfg, bl); err != nil {
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
	// Management-port allow LAST => inserted right after the prelude, above every
	// other rule (even the blacklist): SSH + the API port must never be cut, or a
	// remote TUN/system switch would lock you out of the box.
	if err := injectManagement(cfg, mgmtPorts); err != nil {
		return nil, err
	}
	if err := injectClashSecret(cfg, clashSecret); err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
}

// injectDNS builds the sing-box dns block from our config. Empty servers => no
// dns block (keep sing-box defaults / TUN's injected resolver). Server types map
// straight to sing-box 1.12+ typed DNS servers; local needs no address.
func injectDNS(cfg map[string]json.RawMessage, d apitypes.DNSConfig) error {
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
		if err := ensureCacheFile(cfg); err != nil {
			return err
		}
		if err := ensureStoreFakeIP(cfg); err != nil {
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
func ensureStoreFakeIP(cfg map[string]json.RawMessage) error {
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
		cf = map[string]any{"enabled": true, "path": "data/cache.db"}
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

// injectEndpoints appends enabled WireGuard/Tailscale exits to endpoints[] and
// returns their tags (to be added to the proxy group). WireGuard peers keep the
// pasted allowed_ips; Tailscale gets a per-tag state dir under data/.
func injectEndpoints(cfg map[string]json.RawMessage, list []apitypes.Endpoint) ([]string, error) {
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
			m = map[string]any{"type": "tailscale", "tag": e.Tag, "auth_key": e.AuthKey, "state_directory": "data/ts-" + e.Tag}
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

func injectOutbounds(cfg map[string]json.RawMessage, nodes []apitypes.Node, extraTags []string) error {
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
	// WireGuard/Tailscale endpoint tags (defined in endpoints[]) are valid group
	// members — append so whitelisted traffic can urltest across nodes + exits.
	tags = append(tags, extraTags...)

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
	if len(bl.Domains) > 0 {
		r, _ := json.Marshal(map[string]any{"domain_suffix": bl.Domains, "action": "reject"})
		reject = append(reject, r)
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
