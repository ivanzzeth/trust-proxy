// Package finalroute persists the Surge-like Final egress: the catch-all
// outbound for traffic that already passed security floors + the ACL allow-gate,
// but matched no explicit L4 rule. Final never opens the gate by itself — an
// empty allow-set still keeps the catch-all at blocked (fail-closed).
package finalroute

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	OutboundProxy   = "proxy"
	OutboundDirect  = "direct"
	OutboundBlocked = "blocked"
)

// Config is the persisted Final setting.
type Config struct {
	// Outbound is proxy | direct | blocked | <node/group tag>.
	Outbound string `json:"outbound"`
}

// Store is a file-backed Final config.
type Store struct {
	path string
	mu   sync.Mutex
	data Config
}

// NewStore opens (or seeds default Final=proxy) at path.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path, data: Config{Outbound: OutboundProxy}}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	if err := Validate(s.data.Outbound); err != nil {
		s.data.Outbound = OutboundProxy
		_ = s.save()
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

// Get returns a copy of the config.
func (s *Store) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// Set validates and persists. Empty outbound becomes proxy.
func (s *Store) Set(c Config) (Config, error) {
	c.Outbound = strings.TrimSpace(c.Outbound)
	if c.Outbound == "" {
		c.Outbound = OutboundProxy
	}
	if err := Validate(c.Outbound); err != nil {
		return s.Get(), err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = c
	return s.data, s.save()
}

// Validate accepts built-ins or a non-empty tag without whitespace.
func Validate(outbound string) error {
	switch outbound {
	case OutboundProxy, OutboundDirect, OutboundBlocked:
		return nil
	}
	if outbound == "" {
		return fmt.Errorf("final outbound is required")
	}
	if strings.ContainsAny(outbound, " \t\n") {
		return fmt.Errorf("invalid final outbound %q", outbound)
	}
	return nil
}

// Resolve picks a live outbound for inject: built-ins pass through; unknown
// member tags fall back to proxy (self-heal).
func Resolve(outbound string, memberTags []string) string {
	outbound = strings.TrimSpace(outbound)
	if outbound == "" {
		return OutboundProxy
	}
	switch outbound {
	case OutboundProxy, OutboundDirect, OutboundBlocked:
		return outbound
	}
	for _, t := range memberTags {
		if t == outbound {
			return outbound
		}
	}
	return OutboundProxy
}
