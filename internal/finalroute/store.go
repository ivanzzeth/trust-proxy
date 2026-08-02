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

	// migratedMarker is written beside final.json the first time we rewrite the
	// abandoned Final=proxy seed to direct. After that, an operator who chooses
	// proxy again is left alone — without the marker, outbound==proxy alone
	// cannot tell "never configured" from "chose proxy".
	migratedMarker = "final-default-direct.migrated"
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

// NewStore opens (or seeds default Final=direct) at path.
//
// Direct (not proxy) is the product default: packs and rule sets still send
// Claude / Google / GitHub / … overseas, but a private CN hostname that is
// neither in geosite-cn nor matched yet by geoip (domain-first dial) must not
// fall into an overseas exit and get RST / hairpinned. Operators who want
// "everything else via proxy" set Final=proxy explicitly.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path, data: Config{Outbound: OutboundDirect}}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if err := s.save(); err != nil {
			return nil, err
		}
		// Fresh install already on direct — mark so a later `final set proxy`
		// is never mistaken for the abandoned seed.
		_ = markMigrated(path)
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	if healAbandonedProxyDefault(&s.data, path) {
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	if err := Validate(s.data.Outbound); err != nil {
		s.data.Outbound = OutboundDirect
		_ = s.save()
	}
	return s, nil
}

// healAbandonedProxyDefault rewrites Final=proxy → direct once per data dir,
// then plants migratedMarker so an intentional proxy choice survives restarts.
func healAbandonedProxyDefault(c *Config, finalPath string) bool {
	if strings.TrimSpace(c.Outbound) != OutboundProxy {
		return false
	}
	if migrated(finalPath) {
		return false
	}
	c.Outbound = OutboundDirect
	_ = markMigrated(finalPath)
	return true
}

func migrated(finalPath string) bool {
	_, err := os.Stat(filepath.Join(filepath.Dir(finalPath), migratedMarker))
	return err == nil
}

func markMigrated(finalPath string) error {
	dir := filepath.Dir(finalPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, migratedMarker), []byte("v1\n"), 0o600)
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

// Get returns a copy of the config.
func (s *Store) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// Set validates and persists. Empty outbound becomes direct.
func (s *Store) Set(c Config) (Config, error) {
	c.Outbound = strings.TrimSpace(c.Outbound)
	if c.Outbound == "" {
		c.Outbound = OutboundDirect
	}
	if err := Validate(c.Outbound); err != nil {
		return s.Get(), err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = c
	if err := s.save(); err != nil {
		return s.data, err
	}
	// Any explicit Set means the operator has an opinion — never re-heal.
	_ = markMigrated(s.path)
	return s.data, nil
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
// member tags fall back to direct (self-heal — same default as an empty Final).
func Resolve(outbound string, memberTags []string) string {
	outbound = strings.TrimSpace(outbound)
	if outbound == "" {
		return OutboundDirect
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
	return OutboundDirect
}
