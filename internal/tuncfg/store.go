// Package tuncfg persists the advanced options for the tun inbound the gateway
// builds in TUN mode (stack / MTU / strict_route / package split-tunnel). These
// only matter when the capture mode is "tun"; in manual/system mode they are
// inert. Kept in a small JSON-backed store mirroring internal/inbound.
package tuncfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

var validStacks = map[string]bool{"system": true, "gvisor": true, "mixed": true}

// Default = gvisor stack, auto MTU, strict route on (matches the previous
// hard-coded tun inbound so existing deployments behave identically).
func defaultConfig() apitypes.TUNConfig {
	return apitypes.TUNConfig{Stack: "gvisor", MTU: 0, StrictRoute: true}
}

// Store is a file-backed TUN config, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data apitypes.TUNConfig
}

// NewStore opens (or seeds) the store at path.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = defaultConfig()
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
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
	return os.WriteFile(s.path, b, 0o644)
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
	return nil
}

func clone(c apitypes.TUNConfig) apitypes.TUNConfig {
	out := apitypes.TUNConfig{Stack: c.Stack, MTU: c.MTU, StrictRoute: c.StrictRoute}
	out.ExcludePackage = append([]string(nil), c.ExcludePackage...)
	out.IncludePackage = append([]string(nil), c.IncludePackage...)
	out.ExcludeProcess = append([]string(nil), c.ExcludeProcess...)
	return out
}
