// Package gateway boots and owns the embedded sing-box instance (the data
// plane), attaches our detection tracker, and hot-reloads a rebuilt config when
// the applied subscription nodes or the egress whitelist change.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// ProxyGroupTag is the outbound group whose members we swap when applying a
// subscription. Whitelisted domains egress through it.
const ProxyGroupTag = "proxy"

// Manager owns the running box and rebuilds it in place when policy changes.
type Manager struct {
	configPath string
	logger     log.Logger
	engine     *detect.Engine

	rebuildMu sync.Mutex // serializes rebuilds

	mu       sync.Mutex
	instance *box.Box
	nodes    []apitypes.Node
	wl       whitelist.Rules
}

// NewManager returns a manager seeded with the initial whitelist and the
// detection engine to attach to the data path.
func NewManager(configPath string, wl whitelist.Rules, engine *detect.Engine) *Manager {
	return &Manager{configPath: configPath, logger: log.StdLogger(), wl: wl, engine: engine}
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

// SetWhitelist sets the egress allow-list and hot-reloads.
func (m *Manager) SetWhitelist(wl whitelist.Rules) error {
	m.mu.Lock()
	m.wl = wl
	m.mu.Unlock()
	return m.rebuild()
}

func (m *Manager) rebuild() error {
	m.rebuildMu.Lock()
	defer m.rebuildMu.Unlock()

	m.mu.Lock()
	nodes, wl := m.nodes, m.wl
	m.mu.Unlock()

	base, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}
	merged, err := buildMergedConfig(base, nodes, wl)
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
	instance.Router().AppendTracker(newDetector(m.engine))
	return instance, nil
}

// buildMergedConfig injects (a) subscription node outbounds + the `proxy` group
// and (b) whitelist allow rules into the route, at the JSON level so sing-box's
// own parser validates the result.
func buildMergedConfig(base []byte, nodes []apitypes.Node, wl whitelist.Rules) ([]byte, error) {
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(base, &cfg); err != nil {
		return nil, err
	}
	if err := injectOutbounds(cfg, nodes); err != nil {
		return nil, err
	}
	if err := injectWhitelist(cfg, wl); err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
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
	if len(wl.Domains) > 0 {
		r, _ := json.Marshal(map[string]any{"domain_suffix": wl.Domains, "action": "route", "outbound": ProxyGroupTag})
		allow = append(allow, r)
	}
	if len(wl.IPs) > 0 {
		r, _ := json.Marshal(map[string]any{"ip_cidr": wl.IPs, "action": "route", "outbound": "direct"})
		allow = append(allow, r)
	}

	// insert before the first reject rule (default-deny catch-all)
	rejectIdx := len(rules)
	for i, raw := range rules {
		var meta struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(raw, &meta)
		if meta.Action == "reject" {
			rejectIdx = i
			break
		}
	}
	merged := make([]json.RawMessage, 0, len(rules)+len(allow))
	merged = append(merged, rules[:rejectIdx]...)
	merged = append(merged, allow...)
	merged = append(merged, rules[rejectIdx:]...)

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
