// Package nodeoverride persists per-tag disable flags for subscription (and
// gateway-exit) nodes. Disabled tags are omitted from Auto/Overseas/urltest at
// inject time. State lives outside the subscription JSON so a refresh cannot
// resurrect a node the operator turned off.
package nodeoverride

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Doc is the on-disk shape.
type Doc struct {
	Disabled []string `json:"disabled"`
}

// Store is a file-backed set of disabled outbound tags.
type Store struct {
	path string
	mu   sync.Mutex
	data Doc
}

// NewStore loads (or creates) the override file at path.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = Doc{Disabled: []string{}}
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	s.data.Disabled = normalize(s.data.Disabled)
	return s, nil
}

func (s *Store) save() error {
	if s.data.Disabled == nil {
		s.data.Disabled = []string{}
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

// Disabled returns a snapshot of disabled tags (sorted, unique).
func (s *Store) Disabled() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.data.Disabled...)
}

// DisabledSet is a lookup map for inject-time filtering.
func (s *Store) DisabledSet() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]bool, len(s.data.Disabled))
	for _, t := range s.data.Disabled {
		out[t] = true
	}
	return out
}

// SetDisabled replaces the whole disabled list.
func (s *Store) SetDisabled(tags []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Disabled = normalize(tags)
	if err := s.save(); err != nil {
		return nil, err
	}
	return append([]string(nil), s.data.Disabled...), nil
}

// SetTag enables or disables one tag. Empty tag is a no-op.
func (s *Store) SetTag(tag string, disabled bool) ([]string, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return s.Disabled(), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	set := map[string]bool{}
	for _, t := range s.data.Disabled {
		set[t] = true
	}
	if disabled {
		set[tag] = true
	} else {
		delete(set, tag)
	}
	s.data.Disabled = setKeys(set)
	if err := s.save(); err != nil {
		return nil, err
	}
	return append([]string(nil), s.data.Disabled...), nil
}

// Restore puts a previous Disabled snapshot back (apply failure rollback).
func (s *Store) Restore(tags []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Disabled = normalize(tags)
	return s.save()
}

// Prune drops disabled tags that are no longer among knownTags (after a
// subscription refresh removed them). Unknown disables are kept until prune.
func (s *Store) Prune(knownTags []string) ([]string, error) {
	known := map[string]bool{}
	for _, t := range knownTags {
		known[strings.TrimSpace(t)] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.data.Disabled[:0]
	for _, t := range s.data.Disabled {
		if known[t] {
			kept = append(kept, t)
		}
	}
	s.data.Disabled = kept
	if err := s.save(); err != nil {
		return nil, err
	}
	return append([]string(nil), s.data.Disabled...), nil
}

func normalize(tags []string) []string {
	set := map[string]bool{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t != "" {
			set[t] = true
		}
	}
	return setKeys(set)
}

func setKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
