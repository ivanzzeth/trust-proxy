// Package nodes is the "brain" side of multi-node management: a registry of
// remote trust-proxy gateways (probes). The brain reverse-proxies the browser's
// /api/nodes/{id}/* calls to each probe's /api with its bearer token, so tokens
// stay server-side and the browser talks to one origin.
package nodes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Node is a registered remote gateway. Token is secret (server-side only).
type Node struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`
}

// Public is a Node without its token (safe to return to the browser).
type Public struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

func idFor(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:])[:12]
}

// Store is a file-backed node registry.
type Store struct {
	path string
	mu   sync.Mutex
	data []Node
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = []Node{}
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
	return os.WriteFile(s.path, b, 0o600) // holds tokens
}

// List returns the public view (no tokens).
func (s *Store) List() []Public {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Public, 0, len(s.data))
	for _, n := range s.data {
		out = append(out, Public{ID: n.ID, Name: n.Name, URL: n.URL})
	}
	return out
}

// Get returns the full node (with token) by id.
func (s *Store) Get(id string) (Node, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.data {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

// Add registers (or updates by URL) a node and persists.
func (s *Store) Add(name, url, token string) (Public, error) {
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if url == "" {
		return Public{}, fmt.Errorf("url is required")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	n := Node{ID: idFor(url), Name: strings.TrimSpace(name), URL: url, Token: token}
	if n.Name == "" {
		n.Name = url
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	replaced := false
	for i := range s.data {
		if s.data[i].ID == n.ID {
			s.data[i] = n
			replaced = true
			break
		}
	}
	if !replaced {
		s.data = append(s.data, n)
	}
	if err := s.save(); err != nil {
		return Public{}, err
	}
	return Public{ID: n.ID, Name: n.Name, URL: n.URL}, nil
}

// Delete removes a node by id.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.data[:0:0]
	found := false
	for _, n := range s.data {
		if n.ID == id {
			found = true
			continue
		}
		out = append(out, n)
	}
	if !found {
		return fmt.Errorf("node %q not found", id)
	}
	s.data = out
	return s.save()
}
