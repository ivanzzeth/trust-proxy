// Package tuncfg persists the advanced options for the tun inbound the gateway
// builds in TUN mode (stack / MTU / strict_route / auto_redirect / address /
// package split-tunnel). These only matter when the capture mode is "tun"; in
// manual/system mode they are inert. Kept in a small JSON-backed store
// mirroring internal/inbound.
package tuncfg

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

var validStacks = map[string]bool{"system": true, "gvisor": true, "mixed": true}

// Default = gvisor stack, auto MTU, strict route on, auto_redirect on (Linux
// Docker/containerd bridge capture). Address empty → gateway fills
// apitypes.DefaultTUNAddresses at inject time.
func Defaults() apitypes.TUNConfig {
	return apitypes.TUNConfig{
		Stack:        "gvisor",
		MTU:          0,
		StrictRoute:  true,
		AutoRedirect: true,
	}
}

// Store is a file-backed TUN config, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data apitypes.TUNConfig
}

// NewStore opens (or seeds) the store at path. Existing files that predate
// auto_redirect get it defaulted on so an upgrade starts capturing container
// egress without a manual toggle — the whole point of the field.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = Defaults()
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	changed := false
	if s.data.Stack == "" {
		s.data.Stack = "gvisor"
		changed = true
	}
	if _, ok := probe["auto_redirect"]; !ok {
		s.data.AutoRedirect = true
		changed = true
	}
	if changed {
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

// Get returns a snapshot.
func (s *Store) Get() apitypes.TUNConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.data)
}

// Set validates and replaces the whole config.
func (s *Store) Set(c apitypes.TUNConfig) (apitypes.TUNConfig, error) {
	if err := validate(c); err != nil {
		return s.Get(), err
	}
	s.mu.Lock()
	s.data = clone(c)
	err := s.save()
	s.mu.Unlock()
	return s.Get(), err
}

func validate(c apitypes.TUNConfig) error {
	if !validStacks[c.Stack] {
		return fmt.Errorf("invalid stack %q (want system|gvisor|mixed)", c.Stack)
	}
	if c.MTU < 0 || c.MTU > 65535 {
		return fmt.Errorf("mtu must be between 0 (auto) and 65535")
	}
	if len(c.ExcludePackage) > 0 && len(c.IncludePackage) > 0 {
		return fmt.Errorf("exclude_package and include_package are mutually exclusive")
	}
	for _, a := range c.Address {
		if _, err := netip.ParsePrefix(a); err != nil {
			return fmt.Errorf("invalid tun address %q: %w", a, err)
		}
	}
	return nil
}

func clone(c apitypes.TUNConfig) apitypes.TUNConfig {
	out := apitypes.TUNConfig{
		Stack:        c.Stack,
		MTU:          c.MTU,
		StrictRoute:  c.StrictRoute,
		AutoRedirect: c.AutoRedirect,
	}
	out.Address = append([]string(nil), c.Address...)
	out.ExcludePackage = append([]string(nil), c.ExcludePackage...)
	out.IncludePackage = append([]string(nil), c.IncludePackage...)
	return out
}
