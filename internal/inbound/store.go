// Package inbound persists the auth policy for the mixed proxy inbound
// (:17070) that the gateway injects into sing-box's inbound. Requiring a
// username/password keeps unauthorized clients (or a rogue process on the
// LAN pointing at the gateway) from egressing through it. Both fields empty
// = disabled = the inbound stays open.
package inbound

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Default = open (no auth); the operator opts into auth from the console.
func defaultAuth() apitypes.InboundAuth {
	return apitypes.InboundAuth{}
}

// Store is a file-backed inbound-auth config, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data apitypes.InboundAuth
}

// NewStore opens (or seeds) the store at path.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = defaultAuth()
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
func (s *Store) Get() apitypes.InboundAuth {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// Set validates and replaces the whole config.
func (s *Store) Set(a apitypes.InboundAuth) (apitypes.InboundAuth, error) {
	if err := validate(a); err != nil {
		return s.Get(), err
	}
	s.mu.Lock()
	s.data = a
	err := s.save()
	s.mu.Unlock()
	return s.Get(), err
}

// validate rejects a half-configured pair: either both empty (disabled/open)
// or both set (enabled). A lone username or password is a footgun.
func validate(a apitypes.InboundAuth) error {
	if (a.Username == "") != (a.Password == "") {
		return fmt.Errorf("username and password must both be set (or both empty to disable auth)")
	}
	return nil
}
