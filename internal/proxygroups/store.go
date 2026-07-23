// Package proxygroups persists proxy-group configuration: whether to auto-build
// one group per detected country from the subscription nodes, plus any
// user-defined groups (filter + strategy). The gateway turns this into sing-box
// selector/urltest group outbounds under the `proxy` selector. sing-box has no
// load-balance group (mihomo-only), so only select/urltest are offered.
package proxygroups

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Group strategies + filter modes.
const (
	TypeSelect  = "select"  // manual pick (sing-box selector)
	TypeURLTest = "urltest" // auto fastest / fallback (sing-box urltest)

	FilterCountry = "country" // Value = ISO code; members = nodes of that country
	FilterRegex   = "regex"   // Value = regexp matched against node tags
	FilterManual  = "manual"  // Nodes = explicit node tags
)

// Group is one user-defined proxy group.
type Group struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Filter string   `json:"filter"`
	Value  string   `json:"value,omitempty"`
	Nodes  []string `json:"nodes,omitempty"`
}

// Config is the persisted proxy-group configuration.
type Config struct {
	AutoCountry bool    `json:"auto_country"`
	Groups      []Group `json:"groups"`
}

func validType(t string) bool   { return t == TypeSelect || t == TypeURLTest }
func validFilter(f string) bool { return f == FilterCountry || f == FilterRegex || f == FilterManual }

// validateGroup normalizes and checks a group.
func validateGroup(g *Group) error {
	g.Name = strings.TrimSpace(g.Name)
	g.Type = strings.TrimSpace(g.Type)
	g.Filter = strings.TrimSpace(g.Filter)
	g.Value = strings.TrimSpace(g.Value)
	if g.Name == "" {
		return fmt.Errorf("group name is required")
	}
	if strings.EqualFold(g.Name, "proxy") || strings.EqualFold(g.Name, "auto") ||
		strings.EqualFold(g.Name, "direct") || strings.EqualFold(g.Name, "blocked") {
		return fmt.Errorf("group name %q is reserved", g.Name)
	}
	if !validType(g.Type) {
		return fmt.Errorf("group %q: type must be select or urltest", g.Name)
	}
	if !validFilter(g.Filter) {
		return fmt.Errorf("group %q: filter must be country, regex or manual", g.Name)
	}
	switch g.Filter {
	case FilterRegex:
		if _, err := regexp.Compile(g.Value); err != nil {
			return fmt.Errorf("group %q: invalid regex %q: %w", g.Name, g.Value, err)
		}
	case FilterCountry:
		if g.Value == "" {
			return fmt.Errorf("group %q: country code is required", g.Name)
		}
		g.Value = strings.ToUpper(g.Value)
	case FilterManual:
		if len(g.Nodes) == 0 {
			return fmt.Errorf("group %q: at least one node is required", g.Name)
		}
	}
	return nil
}

// Store is a file-backed proxy-group config, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data Config
}

// NewStore opens (or seeds) the store. A fresh store enables auto-country
// grouping with no custom groups.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = Config{AutoCountry: true, Groups: []Group{}}
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	if s.data.Groups == nil {
		s.data.Groups = []Group{}
	}
	if n := s.sanitize(); n > 0 {
		_ = s.save()
	}
	return s, nil
}

// sanitize drops invalid groups; returns the count removed.
func (s *Store) sanitize() int {
	removed := 0
	out := s.data.Groups[:0:0]
	seen := map[string]bool{}
	for _, g := range s.data.Groups {
		if err := validateGroup(&g); err != nil || seen[strings.ToLower(g.Name)] {
			removed++
			continue
		}
		seen[strings.ToLower(g.Name)] = true
		out = append(out, g)
	}
	s.data.Groups = out
	return removed
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

// Get returns a copy of the current config.
func (s *Store) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return snapshot(s.data)
}

func snapshot(c Config) Config {
	return Config{AutoCountry: c.AutoCountry, Groups: append([]Group(nil), c.Groups...)}
}

// Set validates and replaces the whole config, then persists. Rejects duplicate
// or invalid group names so a bad config never reaches the data plane.
func (s *Store) Set(c Config) (Config, error) {
	groups := make([]Group, 0, len(c.Groups))
	seen := map[string]bool{}
	for _, g := range c.Groups {
		if err := validateGroup(&g); err != nil {
			return s.Get(), err
		}
		if seen[strings.ToLower(g.Name)] {
			return s.Get(), fmt.Errorf("duplicate group name %q", g.Name)
		}
		seen[strings.ToLower(g.Name)] = true
		groups = append(groups, g)
	}
	s.mu.Lock()
	s.data = Config{AutoCountry: c.AutoCountry, Groups: groups}
	snap := snapshot(s.data)
	err := s.save()
	s.mu.Unlock()
	return snap, err
}
