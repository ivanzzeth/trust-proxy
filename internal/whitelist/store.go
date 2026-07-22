// Package whitelist persists the egress allow-list (domains + IP CIDRs) that
// the gateway injects into its route rules. Default-deny: only these egress.
package whitelist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Rules is the allow-list snapshot.
type Rules struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
}

// Store is a file-backed allow-list, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data Rules
}

// DefaultDomains seed a fresh store so the gateway is usable out of the box;
// edit them in the console's Whitelist page.
var DefaultDomains = []string{"example.com", "api.ipify.org", "github.com", "githubusercontent.com"}

// DefaultIPs allows LAN/loopback by default.
var DefaultIPs = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// NewStore opens (or seeds) the store at path.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = Rules{Domains: append([]string(nil), DefaultDomains...), IPs: append([]string(nil), DefaultIPs...)}
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

// Get returns a copy of the current rules.
func (s *Store) Get() Rules {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Rules{Domains: append([]string(nil), s.data.Domains...), IPs: append([]string(nil), s.data.IPs...)}
}

func add(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	list = append(list, v)
	sort.Strings(list)
	return list
}

func remove(list []string, v string) []string {
	out := list[:0:0]
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// AddDomain / RemoveDomain / AddIP / RemoveIP mutate and persist, returning the
// new snapshot.
func (s *Store) AddDomain(d string) (Rules, error) {
	return s.mutate(func() { s.data.Domains = add(s.data.Domains, d) })
}
func (s *Store) RemoveDomain(d string) (Rules, error) {
	return s.mutate(func() { s.data.Domains = remove(s.data.Domains, d) })
}
func (s *Store) AddIP(ip string) (Rules, error) {
	return s.mutate(func() { s.data.IPs = add(s.data.IPs, ip) })
}
func (s *Store) RemoveIP(ip string) (Rules, error) {
	return s.mutate(func() { s.data.IPs = remove(s.data.IPs, ip) })
}

func (s *Store) mutate(fn func()) (Rules, error) {
	s.mu.Lock()
	fn()
	snap := Rules{Domains: append([]string(nil), s.data.Domains...), IPs: append([]string(nil), s.data.IPs...)}
	err := s.save()
	s.mu.Unlock()
	return snap, err
}
