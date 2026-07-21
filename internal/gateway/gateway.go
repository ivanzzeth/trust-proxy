// Package gateway boots and owns the embedded sing-box instance (the data
// plane), attaches our detection tracker, and supports hot-reloading a new
// config (used to apply subscription nodes into the `proxy` group).
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

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// ProxyGroupTag is the outbound group whose members we swap when applying a
// subscription. The base config routes allow-listed egress to this tag.
const ProxyGroupTag = "proxy"

// Manager owns the running box and can rebuild it in place.
type Manager struct {
	configPath string
	logger     log.Logger

	mu       sync.Mutex
	instance *box.Box
}

// NewManager returns a manager for the given base config path.
func NewManager(configPath string) *Manager {
	return &Manager{configPath: configPath, logger: log.StdLogger()}
}

// Start builds and starts the box from the base config.
func (m *Manager) Start() error {
	base, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}
	inst, err := m.buildBox(base)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.instance = inst
	m.mu.Unlock()
	return inst.Start()
}

// Close stops the running box.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.instance == nil {
		return nil
	}
	return m.instance.Close()
}

// Apply rebuilds the box from the base config with the given subscription nodes
// injected as outbounds and wired into the `proxy` group, then swaps it in.
// Passing no nodes resets the group to direct-only.
func (m *Manager) Apply(nodes []apitypes.Node) error {
	base, err := os.ReadFile(m.configPath)
	if err != nil {
		return err
	}
	merged, err := mergeNodes(base, nodes)
	if err != nil {
		return err
	}
	newInst, err := m.buildBox(merged)
	if err != nil {
		return fmt.Errorf("build merged config: %w", err)
	}

	// Free the listeners before starting the new instance (they bind the same
	// ports), so there is a brief blip during reload.
	m.mu.Lock()
	old := m.instance
	m.mu.Unlock()
	if old != nil {
		old.Close()
	}
	if err := newInst.Start(); err != nil {
		return fmt.Errorf("start merged config: %w", err)
	}
	m.mu.Lock()
	m.instance = newInst
	m.mu.Unlock()
	m.logger.Info("gateway reloaded with ", len(nodes), " subscription node(s)")
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
	instance.Router().AppendTracker(newDetector(m.logger))
	return instance, nil
}

// mergeNodes injects node outbounds into the config's outbounds array and sets
// the `proxy` group's members. Works at the JSON level so we don't hand-build
// typed option structs; sing-box's own parser validates the result.
func mergeNodes(base []byte, nodes []apitypes.Node) ([]byte, error) {
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(base, &cfg); err != nil {
		return nil, err
	}
	var outs []json.RawMessage
	if raw, ok := cfg["outbounds"]; ok {
		if err := json.Unmarshal(raw, &outs); err != nil {
			return nil, err
		}
	}

	// Keep base outbounds except the placeholder proxy group (we rebuild it).
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

	// Append node outbounds with de-duplicated tags.
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

	// Rebuild the proxy group: urltest over the nodes (auto-select fastest),
	// or a selector pointing at direct when there are no nodes.
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
		return nil, err
	}
	kept = append(kept, groupRaw)

	newOuts, err := json.Marshal(kept)
	if err != nil {
		return nil, err
	}
	cfg["outbounds"] = newOuts
	return json.Marshal(cfg)
}

func stringOr(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}
