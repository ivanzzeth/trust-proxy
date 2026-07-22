// Package profile persists named policy bundles (applied subscription +
// whitelist snapshot + enabled rule-set tags + optional capture mode) that the
// user one-click switches between. A profile orchestrates the other stores; it
// is a snapshot, not a parallel source of truth.
package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Store is a file-backed, ordered collection of profiles.
type Store struct {
	path string
	mu   sync.Mutex
	data []apitypes.Profile
}

func idFor(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])[:12]
}

// NewStore opens (or seeds an empty) store at path.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = []apitypes.Profile{}
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

// List returns a snapshot of all profiles (never nil, so it serializes as []).
func (s *Store) List() []apitypes.Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append(make([]apitypes.Profile, 0, len(s.data)), s.data...)
}

// Get returns a profile by id.
func (s *Store) Get(id string) (apitypes.Profile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.data {
		if p.ID == id {
			return p, true
		}
	}
	return apitypes.Profile{}, false
}

// Add inserts (or overwrites by id, from its name) a profile and persists.
func (s *Store) Add(p apitypes.Profile) (apitypes.Profile, error) {
	if p.Name == "" {
		return apitypes.Profile{}, fmt.Errorf("profile name is required")
	}
	p.ID = idFor(p.Name)
	s.mu.Lock()
	defer s.mu.Unlock()
	replaced := false
	for i := range s.data {
		if s.data[i].ID == p.ID {
			p.Active = s.data[i].Active
			s.data[i] = p
			replaced = true
			break
		}
	}
	if !replaced {
		s.data = append(s.data, p)
	}
	return p, s.save()
}

// Delete removes a profile by id.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.data[:0:0]
	found := false
	for _, p := range s.data {
		if p.ID == id {
			found = true
			continue
		}
		out = append(out, p)
	}
	if !found {
		return fmt.Errorf("profile %q not found", id)
	}
	s.data = out
	return s.save()
}

// SetActive marks id active and clears the flag on the others.
func (s *Store) SetActive(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for i := range s.data {
		if s.data[i].ID == id {
			found = true
		}
		s.data[i].Active = s.data[i].ID == id
	}
	if !found {
		return fmt.Errorf("profile %q not found", id)
	}
	return s.save()
}
