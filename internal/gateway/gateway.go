// Package gateway boots and owns the embedded sing-box instance (the data
// plane), attaches our detection tracker, and hot-reloads a rebuilt config when
// the applied subscription nodes or the egress whitelist change.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
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
	"github.com/ivanzzeth/trust-proxy/internal/finalroute"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// ProxyGroupTag is the outbound group whose members we swap when applying a
// subscription. Whitelisted domains egress through it.
const ProxyGroupTag = "proxy"

// Operating modes: how the gateway captures traffic.
const (
	ModeManual = "manual" // mixed inbound only; apps point at 127.0.0.1:21584
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
	logWriter   io.Writer // sink for sing-box's own log lines (async ring; nil = stderr)
	engine      *detect.Engine
	clashSecret string

	rebuildMu sync.Mutex // serializes rebuilds

	mu        sync.Mutex
	instance  *box.Box
	nodes     []apitypes.Node
	wl        whitelist.Rules
	bl        blacklist.Rules
	quar      quarantine.List
	onRebuild func()
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
	final     string // catch-all egress when ACL gate is open (default proxy)
	posture   string // strict|split — Split skips L3 permit gate (default-allow)

	// mode dead-man's switch (remote-safety): a guarded mode switch auto-reverts
	// unless confirmed in time.
	guardMu     sync.Mutex
	revertTimer *time.Timer
	revertTo    string
	revertAt    time.Time
}

// SetLogWriter routes sing-box's own log lines to w (the async ring) instead of
// stderr. Must be called before Start; nil restores sing-box's default.
func (m *Manager) SetLogWriter(w io.Writer) {
	m.mu.Lock()
	m.logWriter = w
	m.mu.Unlock()
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
	return m.setAndRebuild("endpoints", func() func() {
		prev := m.endpoints
		m.endpoints = eps
		return func() { m.endpoints = prev }
	})
}

// setAndRebuild runs mutate under m.mu — mutate must swap in the new value and
// return a closure that restores the previous one — then rebuilds the box. If
// the rebuild fails, it restores the previous value under m.mu and rebuilds
// again (best-effort) so the gateway stays up rather than going down with a
// bad config. This is the shared revert-on-failure pattern used by every
// Set* method below; `what` names the setting for the returned error.
func (m *Manager) setAndRebuild(what string, mutate func() (revert func())) error {
	m.mu.Lock()
	revert := mutate()
	m.mu.Unlock()
	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		revert()
		m.mu.Unlock()
		_ = m.rebuild() // best-effort restore
		return fmt.Errorf("apply %s failed (reverted): %w", what, err)
	}
	return nil
}

// NewManager returns a manager seeded with the initial whitelist, the detection
// engine, and the Clash API secret to inject into the config.
func NewManager(configPath, dataDir string, wl whitelist.Rules, engine *detect.Engine, clashSecret string) *Manager {
	return &Manager{
		configPath: configPath, dataDir: dataDir, logger: log.StdLogger(),
		wl: wl, engine: engine, clashSecret: clashSecret, mode: ModeManual,
		final: "proxy", posture: apitypes.PostureStrict,
	}
}

// SetInitialPosture sets the Strict|Split posture used by the first Start().
func (m *Manager) SetInitialPosture(p string) {
	if !apitypes.ValidPosture(p) {
		return
	}
	m.mu.Lock()
	m.posture = p
	m.mu.Unlock()
}

// Posture returns the current Strict|Split posture.
func (m *Manager) Posture() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.posture == "" {
		return apitypes.PostureStrict
	}
	return m.posture
}

// SetPosture switches Strict|Split and hot-reloads. Slot swap / seeding is the
// API layer's job — this only updates the data-plane gate semantics.
func (m *Manager) SetPosture(p string) error {
	if !apitypes.ValidPosture(p) {
		return fmt.Errorf("invalid posture %q", p)
	}
	return m.setAndRebuild("posture", func() func() {
		prev := m.posture
		m.posture = p
		return func() { m.posture = prev }
	})
}

// SetInitialFinal sets the catch-all egress used by the first Start().
func (m *Manager) SetInitialFinal(outbound string) {
	if outbound == "" {
		outbound = "proxy"
	}
	m.mu.Lock()
	m.final = outbound
	m.mu.Unlock()
}

// Final returns the configured catch-all egress (before live self-heal).
func (m *Manager) Final() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.final == "" {
		return "proxy"
	}
	return m.final
}

// SetFinal sets the catch-all egress for allowed-but-unrouted traffic and
// hot-reloads. Empty allow-set still denies all — Final never opens the gate.
func (m *Manager) SetFinal(outbound string) error {
	if outbound == "" {
		outbound = "proxy"
	}
	if err := finalroute.Validate(outbound); err != nil {
		return err
	}
	return m.setAndRebuild("final", func() func() {
		prev := m.final
		m.final = outbound
		return func() { m.final = prev }
	})
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
	m.revertAt = time.Now().Add(revertAfter)
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

// SetInitialNodes sets the subscription nodes used by the first Start() (before
// the box runs), so a restart re-applies the previously-applied subscription
// instead of dropping to a direct-only proxy group.
func (m *Manager) SetInitialNodes(nodes []apitypes.Node) {
	m.mu.Lock()
	m.nodes = nodes
	m.mu.Unlock()
}

// Nodes returns a copy of the currently applied subscription nodes.
func (m *Manager) Nodes() []apitypes.Node {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]apitypes.Node(nil), m.nodes...)
}

// Apply sets the subscription nodes and hot-reloads (empty resets the proxy
// group to direct-only). On rebuild failure it reverts to the previous nodes
// so the gateway stays up rather than going down with a bad config.
func (m *Manager) Apply(nodes []apitypes.Node) error {
	return m.setAndRebuild("nodes", func() func() {
		prev := m.nodes
		m.nodes = nodes
		return func() { m.nodes = prev }
	})
}

// SetWhitelist sets the egress allow-list and hot-reloads. On rebuild failure
// (e.g. a malformed entry) it reverts to the previous list so the gateway stays
// up rather than going down with a bad config.
func (m *Manager) SetWhitelist(wl whitelist.Rules) error {
	return m.setAndRebuild("whitelist", func() func() {
		prev := m.wl
		m.wl = wl
		return func() { m.wl = prev }
	})
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
	return m.setAndRebuild("blacklist", func() func() {
		prev := m.bl
		m.bl = bl
		return func() { m.bl = prev }
	})
}

// SetOnRebuild registers a callback fired after every successful (re)build, so
// host-level observers can re-baseline against the routes the new data plane
// just installed.
func (m *Manager) SetOnRebuild(fn func()) {
	m.mu.Lock()
	m.onRebuild = fn
	m.mu.Unlock()
}

// SetInitialQuarantine seeds the gateway-owned block list used by the first
// Start(). Separate from the deny list on purpose: see internal/quarantine.
func (m *Manager) SetInitialQuarantine(q quarantine.List) {
	m.mu.Lock()
	m.quar = q
	m.mu.Unlock()
}

// SetQuarantine replaces the gateway-owned block list and hot-reloads.
func (m *Manager) SetQuarantine(q quarantine.List) error {
	return m.setAndRebuild("quarantine", func() func() {
		prev := m.quar
		m.quar = q
		return func() { m.quar = prev }
	})
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
	return m.setAndRebuild("no-proxy list", func() func() {
		prev := m.dl
		m.dl = dl
		return func() { m.dl = prev }
	})
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
	return m.setAndRebuild("custom rules", func() func() {
		prev := m.cr
		m.cr = cr
		return func() { m.cr = prev }
	})
}

// SetInitialProxyGroups sets the proxy-group config used by the first Start().
func (m *Manager) SetInitialProxyGroups(pg proxygroups.Config) {
	m.mu.Lock()
	m.pg = pg
	m.mu.Unlock()
}

// SetProxyGroups sets the proxy-group config and hot-reloads (reverts on failure).
func (m *Manager) SetProxyGroups(pg proxygroups.Config) error {
	return m.setAndRebuild("proxy groups", func() func() {
		prev := m.pg
		m.pg = pg
		return func() { m.pg = prev }
	})
}

// SetInitialRuleSets sets the imported rule sets used by the first Start().
func (m *Manager) SetInitialRuleSets(sets ruleset.Sets) {
	m.mu.Lock()
	m.rulesets = sets
	m.mu.Unlock()
}

// SetRuleSets sets the imported rule sets and hot-reloads (reverts on failure).
func (m *Manager) SetRuleSets(sets ruleset.Sets) error {
	return m.setAndRebuild("rule sets", func() func() {
		prev := m.rulesets
		m.rulesets = sets
		return func() { m.rulesets = prev }
	})
}

// SetInitialDNS sets the DNS config used by the first Start().
func (m *Manager) SetInitialDNS(d apitypes.DNSConfig) {
	m.mu.Lock()
	m.dns = d
	m.mu.Unlock()
}

// SetDNS sets the resolver policy and hot-reloads (reverts on failure).
func (m *Manager) SetDNS(d apitypes.DNSConfig) error {
	return m.setAndRebuild("DNS", func() func() {
		prev := m.dns
		m.dns = d
		return func() { m.dns = prev }
	})
}

// SetInitialInbound sets the mixed-inbound auth used by the first Start().
func (m *Manager) SetInitialInbound(a apitypes.InboundAuth) {
	m.mu.Lock()
	m.inbound = a
	m.mu.Unlock()
}

// SetInbound sets the mixed-inbound auth and hot-reloads (reverts on failure).
func (m *Manager) SetInbound(a apitypes.InboundAuth) error {
	return m.setAndRebuild("inbound auth", func() func() {
		prev := m.inbound
		m.inbound = a
		return func() { m.inbound = prev }
	})
}

// SetInitialTUN sets the tun-inbound options used by the first Start().
func (m *Manager) SetInitialTUN(t apitypes.TUNConfig) {
	m.mu.Lock()
	m.tun = t
	m.mu.Unlock()
}

// SetTUN sets the tun-inbound options and hot-reloads (reverts on failure).
func (m *Manager) SetTUN(t apitypes.TUNConfig) error {
	return m.setAndRebuild("TUN options", func() func() {
		prev := m.tun
		m.tun = t
		return func() { m.tun = prev }
	})
}

// ApplyProfile atomically applies a full policy snapshot (nodes + ACL lists +
// custom rules + rule sets + proxy groups + DNS + optional mode) and rebuilds
// ONCE. mode=="" keeps the current capture mode. On failure the previous
// manager state is restored and rebuild is attempted.
func (m *Manager) ApplyProfile(
	nodes []apitypes.Node,
	wl whitelist.Rules,
	bl blacklist.Rules,
	dl directlist.Rules,
	cr customrules.Rules,
	sets ruleset.Sets,
	pg proxygroups.Config,
	dns apitypes.DNSConfig,
	mode string,
	final string,
	posture string,
) error {
	m.mu.Lock()
	prevNodes, prevWL, prevBL, prevDL, prevCR := m.nodes, m.wl, m.bl, m.dl, m.cr
	prevSets, prevPG, prevDNS, prevMode, prevFinal, prevPosture := m.rulesets, m.pg, m.dns, m.mode, m.final, m.posture
	m.nodes = nodes
	m.wl = wl
	m.bl = bl
	m.dl = dl
	m.cr = cr
	m.rulesets = sets
	m.pg = pg
	m.dns = dns
	if mode != "" && validMode(mode) {
		m.mode = mode
	}
	if final != "" {
		m.final = final
	}
	if apitypes.ValidPosture(posture) {
		m.posture = posture
	}
	m.mu.Unlock()

	if err := m.rebuild(); err != nil {
		m.mu.Lock()
		m.nodes, m.wl, m.bl, m.dl, m.cr = prevNodes, prevWL, prevBL, prevDL, prevCR
		m.rulesets, m.pg, m.dns, m.mode, m.final, m.posture = prevSets, prevPG, prevDNS, prevMode, prevFinal, prevPosture
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
	nodes, wl, bl, quar, dl, cr, pg, mode, sets, dns, inbound, tun, eps, mgmt, final, posture :=
		m.nodes, m.wl, m.bl, m.quar, m.dl, m.cr, m.pg, m.mode, m.rulesets, m.dns, m.inbound, m.tun, m.endpoints, m.mgmtPorts, m.final, m.posture
	m.mu.Unlock()

	base, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}
	merged, err := buildMergedConfig(base, nodes, wl, bl, quar, dl, cr, pg, mode, sets, dns, inbound, tun, eps, mgmt, final, posture, m.clashSecret, m.dataDir)
	if err != nil {
		return fmt.Errorf("build config: %w", err)
	}
	newInst, err := m.buildBox(merged)
	if err != nil {
		return fmt.Errorf("build box: %w", err)
	}

	// Free listeners before starting the new instance (same ports): brief blip.
	// m.instance is cleared before Close() so that if Start() below fails, we
	// don't leave a dangling reference to an already-closed box around — a
	// later revert-and-rebuild would otherwise double-Close() it.
	m.mu.Lock()
	old := m.instance
	m.instance = nil
	m.mu.Unlock()
	if old != nil {
		old.Close()
	}
	if err := newInst.Start(); err != nil {
		m.logger.Error("gateway rebuild: new box failed to start after closing the previous instance; gateway has no running box until the next successful rebuild: ", err)
		return fmt.Errorf("start box: %w", err)
	}
	m.mu.Lock()
	m.instance = newInst
	m.mu.Unlock()
	m.logger.Info("gateway reloaded (", len(nodes), " node(s), ", len(wl.Domains), " domain(s), ", len(wl.IPs), " ip(s))")
	m.mu.Lock()
	onRebuild := m.onRebuild
	m.mu.Unlock()
	if onRebuild != nil {
		onRebuild() // e.g. re-baseline the host route watcher against the new plane
	}
	return nil
}

func (m *Manager) buildBox(configBytes []byte) (*box.Box, error) {
	ctx := service.ContextWith(context.Background(), deprecated.NewStderrManager(m.logger))
	ctx = include.Context(ctx)

	options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, configBytes)
	if err != nil {
		return nil, err
	}
	// DefaultLogWriter (our sing-box fork): sing-box formats and writes one line
	// per connection ON the connection goroutine, so the sink must not be a file.
	// nil => sing-box keeps its own stderr default (foreground runs).
	instance, err := box.New(box.Options{Context: ctx, Options: options, DefaultLogWriter: m.logWriter})
	if err != nil {
		return nil, err
	}
	if os.Getenv("TP_NO_DETECTOR") == "" {
		det := newDetector(m.engine)
		instance.Router().AppendTracker(det)
		// The same detector also watches the resolver: queries that never become
		// connections (NXDOMAIN sweeps, TXT tunnels) are invisible to a connection
		// tracker. box.New registers the DNS router into the context we passed.
		if dnsRouter := service.FromContext[adapter.DNSRouter](ctx); dnsRouter != nil {
			dnsRouter.AppendQueryTracker(det)
		}
	}
	return instance, nil
}

// buildMergedConfig assembles the running config from the base + current policy,
// laying route.rules out in strict layers (first-match, top to bottom):
//
//	L0 management rescue   source_port -> direct        (injectManagement, top)
//	L1 security floor      blacklist / deny rule_sets /
//	                       process+device invert -> reject
//	L2 Global bypass       clash_mode=Global -> proxy   (injectClashModeGlobal)
//	L3 Permit gate         NOT(permit-set) -> blocked   (injectAllow; skipped in Split)
//	L4 Route egress        custom / no-proxy / route-* rule_sets
//	   catch-all           network matcher -> Final (gate present OR Split) / blocked
//
// Permit ⊥ Route: route-only sources (no-proxy, route-direct/proxy) never join
// the L3 permit-set. Final never opens an empty gate under Strict; Split skips
// the gate (default-allow) so Final applies to unrouted traffic.
//
// The split keeps two orthogonal concerns apart: the whitelist decides only
// allow/deny (L3), the no-proxy list + rule-sets decide only egress (L4). All
// injection is at the JSON level so sing-box's own parser validates the result.
func buildMergedConfig(base []byte, nodes []apitypes.Node, wl whitelist.Rules, bl blacklist.Rules, quar quarantine.List, dl directlist.Rules, cr customrules.Rules, pg proxygroups.Config, mode string, sets ruleset.Sets, dns apitypes.DNSConfig, inbound apitypes.InboundAuth, tun apitypes.TUNConfig, endpoints []apitypes.Endpoint, mgmtPorts []int, final, posture, clashSecret, dataDir string) ([]byte, error) {
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
	memberTags, loopback, err := injectOutbounds(cfg, nodes, epTags, pg)
	if err != nil {
		return nil, err
	}
	// Before applyMode: a configured dns block is installed first; applyMode's
	// TUN path then runs sanitizeTunDNS so any type=local servers cannot loop.
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
	// Same floor, separate source: what the gateway blocked by itself survives a
	// posture switch that replaces the operator's deny list.
	if err := injectQuarantine(cfg, quar); err != nil {
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
	// L3 ACL gate + L4 routing egress + catch-all Final flip. Needs whitelist +
	// allow-rule-set tags + no-proxy list + custom rules together (they form one
	// allow-set); memberTags validates custom `node` targets and Final tags.
	if err := injectAllow(cfg, wl, sets, dl, cr, memberTags, final, posture); err != nil {
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
	// Safety contracts last: TUN DNS/hijack, DNS-follows-route split, no loopback
	// in Auto when remotes exist. Never widens the ACL allow-set.
	if err := applyInvariants(cfg, mode, loopback, dns, ruleset.DNSSafeTags(sets)); err != nil {
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
