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
	"path/filepath"
	"regexp"
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
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
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
	dataDir     string // where cache.db / tailscale state live (default ~/.trust-proxy)
	logger      log.Logger
	engine      *detect.Engine
	clashSecret string

	rebuildMu sync.Mutex // serializes rebuilds

	mu        sync.Mutex
	instance  *box.Box
	nodes     []apitypes.Node
	wl        whitelist.Rules
	bl        blacklist.Rules
	dl        directlist.Rules
	cr        customrules.Rules
	pg        proxygroups.Config
	mode      string
	rulesets  ruleset.Sets
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
func NewManager(configPath, dataDir string, wl whitelist.Rules, engine *detect.Engine, clashSecret string) *Manager {
	return &Manager{configPath: configPath, dataDir: dataDir, logger: log.StdLogger(), wl: wl, engine: engine, clashSecret: clashSecret, mode: ModeManual}
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

// truncVals returns at most n values, appending a "(+K more)" marker if the
// slice was longer — keeps the explain view readable for big rule-sets.
func truncVals(vals []string, n int) []string {
	if len(vals) <= n {
		return append([]string(nil), vals...)
	}
	out := append([]string(nil), vals[:n]...)
	return append(out, fmt.Sprintf("(+%d more)", len(vals)-n))
}

// EffectiveRules projects the current policy into the ordered, layer-labeled
// view the "why is this allowed/blocked" UI renders. It mirrors, in the SAME
// order, the rules buildMergedConfig injects — but derived directly from the
// stores (the merged config isn't retained). The drift test in gateway_test.go
// asserts the layer sequence here matches a freshly built merged config.
func (m *Manager) EffectiveRules() []apitypes.RuleView {
	m.mu.Lock()
	wl, bl, dl, cr, pg, sets, mode, mgmt, nodes, eps := m.wl, m.bl, m.dl, m.cr, m.pg, m.rulesets, m.mode, m.mgmtPorts, m.nodes, m.endpoints
	m.mu.Unlock()

	var epTags []string
	for _, e := range eps {
		if e.Enabled && e.Tag != "" {
			epTags = append(epTags, e.Tag)
		}
	}
	// Valid custom `node` targets = individual nodes/endpoints ∪ group tags
	// (mirrors injectOutbounds), so a rule pointing at a group isn't flagged stale.
	nodeT := memberTags(nodes, epTags)
	_, groupT := buildProxyGroups(nodeT, pg)
	members := map[string]bool{}
	for _, t := range append(append([]string(nil), nodeT...), groupT...) {
		members[t] = true
	}

	var out []apitypes.RuleView
	add := func(v apitypes.RuleView) { out = append(out, v) }

	// prelude: sniff (+ TUN hijack-dns).
	add(apitypes.RuleView{Layer: "prelude", Source: "sniff", Action: "sniff", Note: "detect SNI/domain"})
	if mode == ModeTUN {
		add(apitypes.RuleView{Layer: "prelude", Source: "hijack-dns", Action: "hijack-dns", Matcher: "protocol"})
	}

	// L0 management rescue (topmost).
	if len(mgmt) > 0 {
		vals := make([]string, len(mgmt))
		for i, p := range mgmt {
			vals[i] = strconv.Itoa(p)
		}
		add(apitypes.RuleView{Layer: "L0", Source: "management", Action: "route:direct", Matcher: "source_port", Values: vals, Note: "SSH/API rescue"})
	}

	// L1 security floor.
	if sfx, rgx := splitDomainMatchers(bl.Domains); len(sfx) > 0 || len(rgx) > 0 {
		if len(sfx) > 0 {
			add(apitypes.RuleView{Layer: "L1", Source: "blacklist", Action: "reject", Matcher: "domain_suffix", Values: truncVals(sfx, 20)})
		}
		if len(rgx) > 0 {
			add(apitypes.RuleView{Layer: "L1", Source: "blacklist", Action: "reject", Matcher: "domain_regex", Values: truncVals(rgx, 20)})
		}
	}
	if len(bl.Keywords) > 0 {
		add(apitypes.RuleView{Layer: "L1", Source: "blacklist", Action: "reject", Matcher: "domain_keyword", Values: truncVals(bl.Keywords, 20)})
	}
	if len(bl.Regexes) > 0 {
		add(apitypes.RuleView{Layer: "L1", Source: "blacklist", Action: "reject", Matcher: "domain_regex", Values: truncVals(bl.Regexes, 20)})
	}
	if len(bl.IPs) > 0 {
		add(apitypes.RuleView{Layer: "L1", Source: "blacklist", Action: "reject", Matcher: "ip_cidr", Values: truncVals(bl.IPs, 20)})
	}
	for _, rs := range sets.Sets {
		if rs.Enabled && rs.Tag != "" && rs.Role == apitypes.RuleRoleBlock {
			add(apitypes.RuleView{Layer: "L1", Source: "rule-set:" + rs.Tag, Action: "reject", Matcher: "rule_set", Values: []string{rs.Tag}})
		}
	}
	if len(wl.Processes) > 0 {
		add(apitypes.RuleView{Layer: "L1", Source: "process", Action: "reject", Matcher: "process (inverted)", Values: truncVals(wl.Processes, 20), Note: "unlisted processes can't egress"})
	}
	if len(wl.Devices) > 0 {
		add(apitypes.RuleView{Layer: "L1", Source: "device", Action: "reject", Matcher: "source_ip_cidr (inverted)", Values: truncVals(wl.Devices, 20), Note: "unlisted source devices can't egress"})
	}

	// L2 Global bypass (always injected; inert in Rule mode).
	add(apitypes.RuleView{Layer: "L2", Source: "global", Action: "route:proxy", Matcher: "clash_mode", Values: []string{"Global"}, Note: "only when routing mode = Global"})

	// L3/L4 depend on whether anything is allowed.
	var directSets, proxySets []string
	allowSetTags := 0
	for _, rs := range sets.Sets {
		if !rs.Enabled || rs.Tag == "" {
			continue
		}
		switch rs.Role {
		case apitypes.RuleRoleAllowDirect:
			directSets = append(directSets, rs.Tag)
			allowSetTags++
		case apitypes.RuleRoleAllowProxy:
			proxySets = append(proxySets, rs.Tag)
			allowSetTags++
		}
	}
	wlSfx, wlRgx := splitDomainMatchers(wl.Domains)
	dlSfx, dlRgx := splitDomainMatchers(dl.Domains)
	hasCustomAllow := false
	for _, r := range cr.Rules {
		if !r.Enabled || r.Action == apitypes.CustomActionBlock {
			continue
		}
		if r.Action == apitypes.CustomActionNode && !members[r.Node] {
			continue
		}
		hasCustomAllow = true
	}
	hasUserAllow := len(wlSfx) > 0 || len(wlRgx) > 0 || len(wl.IPs) > 0 ||
		len(dlSfx) > 0 || len(dlRgx) > 0 || len(dl.IPs) > 0 || allowSetTags > 0 || hasCustomAllow

	if !hasUserAllow {
		add(apitypes.RuleView{Layer: "catch-all", Source: "default-deny", Action: "route:blocked", Matcher: "network", Note: "nothing allowed → everything blocked (fail-closed)"})
		return out
	}

	// L3 ACL gate.
	var allowBits []string
	if n := len(wlSfx) + len(wlRgx) + len(wl.IPs); n > 0 {
		allowBits = append(allowBits, fmt.Sprintf("whitelist(%d)", n))
	}
	if n := len(dlSfx) + len(dlRgx) + len(dl.IPs); n > 0 {
		allowBits = append(allowBits, fmt.Sprintf("no-proxy(%d)", n))
	}
	if allowSetTags > 0 {
		allowBits = append(allowBits, fmt.Sprintf("rule-sets(%d)", allowSetTags))
	}
	allowBits = append(allowBits, "private-CIDRs")
	add(apitypes.RuleView{Layer: "L3", Source: "acl-gate", Action: "route:blocked", Matcher: "logical (inverted)", Values: allowBits, Note: "anything NOT in the allow-set is blocked"})

	// L4 routing egress, in injection order: custom → rule-set direct →
	// no-proxy domains → no-proxy+private IPs → rule-set proxy.
	for _, r := range cr.Rules {
		if !r.Enabled {
			continue
		}
		key, ok := customrules.SingboxMatchKey(r.Match)
		if !ok || r.Value == "" {
			continue
		}
		v := apitypes.RuleView{Layer: "L4", Source: "custom", Matcher: key, Values: []string{r.Value}}
		switch r.Action {
		case apitypes.CustomActionDirect:
			v.Action = "route:direct"
		case apitypes.CustomActionProxy:
			if r.Node != "" && members[r.Node] {
				v.Action = "route:" + r.Node
			} else {
				v.Action = "route:proxy"
				if r.Node != "" {
					v.Note = "group " + r.Node + " missing — via proxy"
				}
			}
		case apitypes.CustomActionBlock:
			v.Action = "route:blocked"
		case apitypes.CustomActionNode:
			v.Action = "route:" + r.Node
			if !members[r.Node] {
				v.Note = "node " + r.Node + " missing — rule skipped"
			}
		}
		add(v)
	}
	for _, tag := range directSets {
		add(apitypes.RuleView{Layer: "L4", Source: "rule-set:" + tag, Action: "route:direct", Matcher: "rule_set", Values: []string{tag}})
	}
	if len(dlSfx) > 0 {
		add(apitypes.RuleView{Layer: "L4", Source: "no-proxy", Action: "route:direct", Matcher: "domain_suffix", Values: truncVals(dlSfx, 20)})
	}
	if len(dlRgx) > 0 {
		add(apitypes.RuleView{Layer: "L4", Source: "no-proxy", Action: "route:direct", Matcher: "domain_regex", Values: truncVals(dlRgx, 20)})
	}
	// no-proxy IPs + built-in private CIDRs always share one direct ip_cidr rule.
	ipVals := append(append([]string(nil), dl.IPs...), privateCIDRs...)
	add(apitypes.RuleView{Layer: "L4", Source: "no-proxy", Action: "route:direct", Matcher: "ip_cidr", Values: truncVals(ipVals, 20), Note: "includes built-in LAN/private ranges"})
	for _, tag := range proxySets {
		add(apitypes.RuleView{Layer: "L4", Source: "rule-set:" + tag, Action: "route:proxy", Matcher: "rule_set", Values: []string{tag}})
	}

	// catch-all default egress (gate present → proxy).
	add(apitypes.RuleView{Layer: "catch-all", Source: "default", Action: "route:proxy", Matcher: "network", Note: "allowed traffic with no explicit egress"})
	return out
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

// SetInitialDirectList sets the no-proxy (bypass) list used by the first Start().
func (m *Manager) SetInitialDirectList(dl directlist.Rules) {
	m.mu.Lock()
	m.dl = dl
	m.mu.Unlock()
}

// SetDirectList sets the no-proxy (bypass) list and hot-reloads. On rebuild
// failure it reverts to the previous list so the gateway stays up.
func (m *Manager) SetDirectList(dl directlist.Rules) error {
	m.mu.Lock()
	prev := m.dl
	m.dl = dl
	m.mu.Unlock()
	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.dl = prev
		m.mu.Unlock()
		_ = m.rebuild() // best-effort restore
		return fmt.Errorf("apply no-proxy list failed (reverted): %w", err)
	}
	return nil
}

// SetInitialCustomRules sets the custom routing rules used by the first Start().
func (m *Manager) SetInitialCustomRules(cr customrules.Rules) {
	m.mu.Lock()
	m.cr = cr
	m.mu.Unlock()
}

// SetCustomRules sets the custom routing rules and hot-reloads. On rebuild
// failure it reverts to the previous rules so the gateway stays up.
func (m *Manager) SetCustomRules(cr customrules.Rules) error {
	m.mu.Lock()
	prev := m.cr
	m.cr = cr
	m.mu.Unlock()
	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.cr = prev
		m.mu.Unlock()
		_ = m.rebuild() // best-effort restore
		return fmt.Errorf("apply custom rules failed (reverted): %w", err)
	}
	return nil
}

// SetInitialProxyGroups sets the proxy-group config used by the first Start().
func (m *Manager) SetInitialProxyGroups(pg proxygroups.Config) {
	m.mu.Lock()
	m.pg = pg
	m.mu.Unlock()
}

// SetProxyGroups sets the proxy-group config and hot-reloads (reverts on failure).
func (m *Manager) SetProxyGroups(pg proxygroups.Config) error {
	m.mu.Lock()
	prev := m.pg
	m.pg = pg
	m.mu.Unlock()
	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.pg = prev
		m.mu.Unlock()
		_ = m.rebuild() // best-effort restore
		return fmt.Errorf("apply proxy groups failed (reverted): %w", err)
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
	nodes, wl, bl, dl, cr, pg, mode, sets, dns, inbound, tun, eps, mgmt := m.nodes, m.wl, m.bl, m.dl, m.cr, m.pg, m.mode, m.rulesets, m.dns, m.inbound, m.tun, m.endpoints, m.mgmtPorts
	m.mu.Unlock()

	base, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}
	merged, err := buildMergedConfig(base, nodes, wl, bl, dl, cr, pg, mode, sets, dns, inbound, tun, eps, mgmt, m.clashSecret, m.dataDir)
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

// buildMergedConfig assembles the running config from the base + current policy,
// laying route.rules out in strict layers (first-match, top to bottom):
//
//	L0 management rescue   source_port -> direct        (injectManagement, top)
//	L1 security floor      blacklist / block rule_sets /
//	                       process+device invert -> reject
//	L2 Global bypass       clash_mode=Global -> proxy   (injectClashModeGlobal)
//	L3 ACL gate            NOT(allow-set) -> blocked     (injectAllow)
//	L4 routing egress      direct-bypass -> direct; else -> proxy (injectAllow)
//	   catch-all           network matcher -> proxy (gate present) / blocked
//
// The split keeps two orthogonal concerns apart: the whitelist decides only
// allow/deny (L3), the no-proxy list + rule-sets decide only egress (L4). All
// injection is at the JSON level so sing-box's own parser validates the result.
func buildMergedConfig(base []byte, nodes []apitypes.Node, wl whitelist.Rules, bl blacklist.Rules, dl directlist.Rules, cr customrules.Rules, pg proxygroups.Config, mode string, sets ruleset.Sets, dns apitypes.DNSConfig, inbound apitypes.InboundAuth, tun apitypes.TUNConfig, endpoints []apitypes.Endpoint, mgmtPorts []int, clashSecret, dataDir string) ([]byte, error) {
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(base, &cfg); err != nil {
		return nil, err
	}
	// WireGuard/Tailscale exits go in endpoints[]; their tags join the proxy group.
	epTags, err := injectEndpoints(cfg, endpoints, dataDir)
	if err != nil {
		return nil, err
	}
	// memberTags = proxy group members (node + endpoint outbounds); the valid
	// targets for a custom rule's `node` action.
	memberTags, err := injectOutbounds(cfg, nodes, epTags, pg)
	if err != nil {
		return nil, err
	}
	// Before applyMode: a configured dns block wins over TUN's default resolver.
	if err := injectDNS(cfg, dns, dataDir); err != nil {
		return nil, err
	}
	if err := applyMode(cfg, mode, inbound, tun); err != nil {
		return nil, err
	}
	// L1 security floor (hard deny). Blacklist rejects go right after the prelude.
	if err := injectBlacklist(cfg, bl); err != nil {
		return nil, err
	}
	// L1: register rule_set descriptors + emit block-role rejects (allow-role
	// egress moved to injectAllow/L4). Anchors on the network-matcher catch-all.
	if err := injectRuleSets(cfg, sets, dataDir, len(nodes) > 0 || len(epTags) > 0); err != nil {
		return nil, err
	}
	// L1: process/device invert rejects (opt-in anti-exfil gates).
	if err := injectProcessDeviceFloor(cfg, wl); err != nil {
		return nil, err
	}
	// L2: Rule<->Global toggle. Runs BEFORE injectAllow so its rule lands ABOVE
	// the ACL gate — in Global mode traffic routes to proxy before the gate can
	// block it; in Rule mode it is inert and the gate applies unchanged.
	if err := injectClashModeGlobal(cfg, dataDir); err != nil {
		return nil, err
	}
	// L3 ACL gate + L4 routing egress + catch-all flip. Needs whitelist +
	// allow-rule-set tags + no-proxy list + custom rules together (they form one
	// allow-set); memberTags validates custom `node` targets.
	if err := injectAllow(cfg, wl, sets, dl, cr, memberTags); err != nil {
		return nil, err
	}
	// L0: management-port allow LAST => inserted right after the prelude, above
	// every other rule: SSH + the API port must never be cut, or a remote
	// TUN/system switch would lock you out of the box.
	if err := injectManagement(cfg, mgmtPorts); err != nil {
		return nil, err
	}
	if err := injectClashSecret(cfg, clashSecret); err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
}

// privateCIDRs are always direct-bypassed (and always in the ACL allow-set):
// LAN / loopback / link-local / CGNAT must never be forced through the proxy or
// blocked by default-deny. This is the built-in floor of the no-proxy list.
var privateCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
	"::1/128", "fc00::/7", "fe80::/10",
}

// PrivateCIDRs returns the built-in LAN/private/reserved ranges that always
// egress direct (and always join the ACL allow-set when a gate is present).
// The API surfaces these as read-only defaults in the No-Proxy view.
func PrivateCIDRs() []string { return append([]string(nil), privateCIDRs...) }

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

// preludeLen returns the number of leading prelude rules (sniff / hijack-dns).
// New floor rules are inserted right after the prelude so they sit above the
// ACL gate; the prelude itself (sniff, then TUN hijack-dns) must stay first.
func preludeLen(rules []json.RawMessage) int {
	n := 0
	for n < len(rules) {
		var m struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(rules[n], &m)
		if m.Action == "sniff" || m.Action == "hijack-dns" {
			n++
			continue
		}
		break
	}
	return n
}

// catchAllIdx returns the index of the default-deny catch-all (the rule carrying
// a bare network matcher — reject or route->blocked), or len(rules) if absent.
// Allow/gate rules are inserted right before it.
func catchAllIdx(rules []json.RawMessage) int {
	for i, r := range rules {
		var m struct {
			Network json.RawMessage `json:"network"`
		}
		_ = json.Unmarshal(r, &m)
		if len(m.Network) > 0 {
			return i
		}
	}
	return len(rules)
}

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
			desc["download_detour"] = detour
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

	// (2) block-role rule_sets -> reject (L1 floor), inserted right after the
	// prelude so they sit above the ACL gate. Allow-role rule_sets are handled
	// by injectAllow.
	var blockTags []string
	for _, rs := range enabled {
		if rs.Role == apitypes.RuleRoleBlock {
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

// buildProxyGroups turns the member pool (node + endpoint tags) into sing-box
// group outbounds and the top-level `proxy` selector. It returns the outbound
// JSON to append AND the group tags (Auto + per-country + user groups, NOT the
// proxy selector) — those extend the valid `node`-action targets. Layering:
//   - Auto: urltest over every member (the default the proxy selector points at,
//     preserving the pre-grouping behavior).
//   - per-country urltest groups (when AutoCountry and ≥1 country is detected).
//   - user groups (select|urltest) by country/regex/manual filter.
//   - proxy: selector over [Auto, country…, user…], default = Auto.
//
// Empty pool => proxy is selector[direct] and there are no groups.
// It is pure (no cfg mutation) so EffectiveRules can reuse it for the member set.
func buildProxyGroups(tags []string, pg proxygroups.Config) (outs []json.RawMessage, groupTags []string) {
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
			g["url"] = "https://www.gstatic.com/generate_204"
			g["interval"] = "3m"
		}
		b, _ := json.Marshal(g)
		outs = append(outs, b)
		groupTags = append(groupTags, tag)
	}

	autoTag := uniq("Auto")
	add("urltest", autoTag, tags)

	if pg.AutoCountry {
		buckets := map[string][]string{}
		var order []string
		real := 0
		for _, t := range tags {
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
// outbound tags PLUS the group tags (Auto / country / user groups). A custom
// rule pinning any other tag is skipped at inject time (self-heal).
func injectOutbounds(cfg map[string]json.RawMessage, nodes []apitypes.Node, extraTags []string, pg proxygroups.Config) ([]string, error) {
	var outs []json.RawMessage
	if raw, ok := cfg["outbounds"]; ok {
		if err := json.Unmarshal(raw, &outs); err != nil {
			return nil, err
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
	}
	// WireGuard/Tailscale endpoint tags (defined in endpoints[]) are valid group
	// members — append so groups can urltest across nodes + exits.
	tags = append(tags, extraTags...)

	groupOuts, groupTags := buildProxyGroups(tags, pg)
	kept = append(kept, groupOuts...)

	newOuts, err := json.Marshal(kept)
	if err != nil {
		return nil, err
	}
	cfg["outbounds"] = newOuts
	// Valid node-action targets = individual nodes/endpoints ∪ the group tags.
	return append(append([]string(nil), tags...), groupTags...), nil
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

// injectAllow builds the ACL gate (L3) and the routing egress (L4), then flips
// the catch-all default egress. It needs the whitelist, the allow-role
// rule-sets, and the no-proxy list together because they jointly define both
// the allow-set (L3) and the direct-bypass set (L4):
//
//	allow-set (L3) = whitelist domains+ips ∪ ALL allow rule_set tags ∪
//	                 no-proxy domains+ips ∪ built-in private CIDRs
//	direct (L4)    = allow-direct rule_sets + no-proxy domains+ips + private CIDRs
//	proxy  (L4)    = allow-proxy rule_sets
//	catch-all      = proxy (gate present) — the egress for allowed-but-unrouted
//
// The gate is ONE logical-or-invert rule that routes anything NOT in the
// allow-set to the `blocked` outbound (NOT action:reject) so blocked
// connections still pass the detector, keep their sniffed SNI, and can be
// one-click allowed. When the allow-set is empty, NO gate is emitted and the
// catch-all stays `blocked` (fail-closed default-deny). The whitelist never
// picks an egress here — that is entirely the no-proxy list's / rule-sets' job.
//
// Custom routing rules (cr) are the ordered, top-priority slice of L4: each
// enabled rule routes its matcher to direct/proxy/blocked/<node>, evaluated in
// order ABOVE the rule-set egress. A direct/proxy/node rule also joins the
// allow-set (it implies "allow"); a block rule does not. A `node` rule whose
// target tag isn't a current outbound (memberTags) is skipped entirely
// (self-heal) so a removed node can't brick the box.
func injectAllow(cfg map[string]json.RawMessage, wl whitelist.Rules, sets ruleset.Sets, dl directlist.Rules, cr customrules.Rules, memberTags []string) error {
	routeRaw, ok := cfg["route"]
	if !ok {
		return nil
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(routeRaw, &route); err != nil {
		return err
	}

	// Allow rule_set tags by egress role (block-role is handled in injectRuleSets).
	var directSetTags, proxySetTags, allowSetTags []string
	for _, rs := range sets.Sets {
		if !rs.Enabled || rs.Tag == "" {
			continue
		}
		switch rs.Role {
		case apitypes.RuleRoleAllowDirect:
			directSetTags = append(directSetTags, rs.Tag)
			allowSetTags = append(allowSetTags, rs.Tag)
		case apitypes.RuleRoleAllowProxy:
			proxySetTags = append(proxySetTags, rs.Tag)
			allowSetTags = append(allowSetTags, rs.Tag)
		}
	}

	wlSfx, wlRgx := splitDomainMatchers(wl.Domains)
	dlSfx, dlRgx := splitDomainMatchers(dl.Domains)

	// Custom routing rules (ordered): build the top-priority L4 egress slice and
	// their allow-set sub-rules in one pass. node rules with a dead tag are
	// skipped (self-heal). block rules route but do NOT join the allow-set.
	members := map[string]bool{}
	for _, t := range memberTags {
		members[t] = true
	}
	var customEgress []json.RawMessage
	var customSubRules []map[string]any
	hasCustomAllow := false
	for _, rule := range cr.Rules {
		if !rule.Enabled {
			continue
		}
		key, ok := customrules.SingboxMatchKey(rule.Match)
		if !ok || rule.Value == "" {
			continue
		}
		var outbound string
		switch rule.Action {
		case apitypes.CustomActionDirect:
			outbound = "direct"
		case apitypes.CustomActionProxy:
			// Optional group target; fall back to the top proxy selector if the
			// named group is gone (still honors "go through proxy").
			outbound = ProxyGroupTag
			if rule.Node != "" && members[rule.Node] {
				outbound = rule.Node
			}
		case apitypes.CustomActionBlock:
			outbound = "blocked"
		case apitypes.CustomActionNode:
			if !members[rule.Node] {
				continue // self-heal: target node isn't a live outbound
			}
			outbound = rule.Node
		default:
			continue
		}
		r, _ := json.Marshal(map[string]any{key: []string{rule.Value}, "action": "route", "outbound": outbound})
		customEgress = append(customEgress, r)
		if rule.Action != apitypes.CustomActionBlock {
			customSubRules = append(customSubRules, map[string]any{key: []string{rule.Value}})
			hasCustomAllow = true
		}
	}

	// Gate ONLY when the user actually allowed something. The built-in private
	// CIDRs are not a user allow: with no whitelist / no-proxy / allow rule-set /
	// custom allow rule, they must NOT open the gate — the catch-all stays
	// blocked (fail-closed).
	hasUserAllow := len(wlSfx) > 0 || len(wlRgx) > 0 || len(wl.IPs) > 0 ||
		len(dlSfx) > 0 || len(dlRgx) > 0 || len(dl.IPs) > 0 || len(allowSetTags) > 0 || hasCustomAllow
	if !hasUserAllow {
		return nil
	}

	// allow-set (L3) matchers = whitelist ∪ no-proxy ∪ private CIDRs ∪ allow sets.
	allowSfx := append(append([]string(nil), wlSfx...), dlSfx...)
	allowRgx := append(append([]string(nil), wlRgx...), dlRgx...)
	allowIPs := append(append(append([]string(nil), wl.IPs...), dl.IPs...), privateCIDRs...)
	// direct-bypass (L4) = no-proxy domains/ips + built-in private CIDRs.
	directIPs := append(append([]string(nil), dl.IPs...), privateCIDRs...)

	// L3 gate: one logical OR of every allow matcher, inverted -> blocked.
	var subRules []map[string]any
	if len(allowSfx) > 0 {
		subRules = append(subRules, map[string]any{"domain_suffix": allowSfx})
	}
	if len(allowRgx) > 0 {
		subRules = append(subRules, map[string]any{"domain_regex": allowRgx})
	}
	if len(allowIPs) > 0 {
		subRules = append(subRules, map[string]any{"ip_cidr": allowIPs})
	}
	if len(allowSetTags) > 0 {
		subRules = append(subRules, map[string]any{"rule_set": allowSetTags})
	}
	subRules = append(subRules, customSubRules...)
	gate, _ := json.Marshal(map[string]any{
		"type": "logical", "mode": "or", "rules": subRules,
		"invert": true, "action": "route", "outbound": "blocked",
	})

	// L4 egress: custom rules first (ordered, user's explicit per-rule intent),
	// then direct-bypass (rule_sets, then no-proxy domains/ips), then allow-proxy
	// sets. Allowed traffic matched by none falls to the catch-all default (proxy).
	var egress []json.RawMessage
	egress = append(egress, customEgress...)
	if len(directSetTags) > 0 {
		r, _ := json.Marshal(map[string]any{"rule_set": directSetTags, "action": "route", "outbound": "direct"})
		egress = append(egress, r)
	}
	if len(dlSfx) > 0 {
		r, _ := json.Marshal(map[string]any{"domain_suffix": dlSfx, "action": "route", "outbound": "direct"})
		egress = append(egress, r)
	}
	if len(dlRgx) > 0 {
		r, _ := json.Marshal(map[string]any{"domain_regex": dlRgx, "action": "route", "outbound": "direct"})
		egress = append(egress, r)
	}
	if len(directIPs) > 0 {
		r, _ := json.Marshal(map[string]any{"ip_cidr": directIPs, "action": "route", "outbound": "direct"})
		egress = append(egress, r)
	}
	if len(proxySetTags) > 0 {
		r, _ := json.Marshal(map[string]any{"rule_set": proxySetTags, "action": "route", "outbound": ProxyGroupTag})
		egress = append(egress, r)
	}

	var rules []json.RawMessage
	if raw, ok := route["rules"]; ok {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return err
		}
	}
	catchIdx := catchAllIdx(rules)

	inserted := make([]json.RawMessage, 0, 1+len(egress))
	inserted = append(inserted, gate)
	inserted = append(inserted, egress...)

	merged := make([]json.RawMessage, 0, len(rules)+len(inserted))
	merged = append(merged, rules[:catchIdx]...)
	merged = append(merged, inserted...)
	merged = append(merged, rules[catchIdx:]...)

	// Flip the catch-all default egress from blocked -> proxy (gate present):
	// allowed traffic that no L4 rule routed egresses via the proxy group.
	newCatchIdx := catchIdx + len(inserted)
	if newCatchIdx < len(merged) {
		var catchRule map[string]any
		if err := json.Unmarshal(merged[newCatchIdx], &catchRule); err == nil {
			if _, hasNet := catchRule["network"]; hasNet {
				catchRule["action"] = "route"
				catchRule["outbound"] = ProxyGroupTag
				if b, err := json.Marshal(catchRule); err == nil {
					merged[newCatchIdx] = b
				}
			}
		}
	}

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

// globToRegex compiles a domain glob (containing * or ?) to an anchored Go
// regex: * => any run of chars, ? => one char, everything else literal.
//
//	*.example.com -> subdomains of example.com
//	foo*          -> prefix match
func globToRegex(g string) string {
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range g {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return b.String()
}

// splitDomainMatchers partitions domain entries into plain suffix matches and
// glob patterns. A plain entry keeps domain_suffix semantics (matches the
// domain + its subdomains); an entry containing * or ? becomes a domain_regex.
// This is how whitelist/blacklist domains gain prefix/suffix/wildcard support
// without a schema change — the match type is encoded in the value itself.
func splitDomainMatchers(domains []string) (suffixes, regexes []string) {
	for _, d := range domains {
		if strings.ContainsAny(d, "*?") {
			regexes = append(regexes, globToRegex(d))
		} else {
			suffixes = append(suffixes, d)
		}
	}
	return
}

func stringOr(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}
