// Package whitelist persists the egress allow-list (domains + IP CIDRs) that
// the gateway injects into its route rules. Default-deny: only these egress.
package whitelist

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// validCIDR reports whether s is a usable ip_cidr entry (a CIDR or a bare IP).
func validCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}

// Rules is the allow-list snapshot.
//   - Domains / IPs: allowed egress destinations (default-deny for the rest).
//   - Processes: OPT-IN process allow-list — when non-empty, any process NOT
//     listed is rejected (unknown binaries can't egress). Path-separator entries
//     match process_path, others process_name.
//   - Devices: OPT-IN source (device) allow-list — when non-empty, any source
//     IP/CIDR NOT listed is rejected (only known devices may egress; for
//     gateway/router deployments). Entries are IPs or CIDRs (source_ip_cidr).
type Rules struct {
	Domains   []string `json:"domains"`
	IPs       []string `json:"ips"`
	Processes []string `json:"processes"`
	Devices   []string `json:"devices"`
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
	// Drop entries that would make the box fail to build (e.g. a domain wrongly
	// stored under IPs), so a poisoned store self-heals instead of bricking the
	// gateway on start.
	if n := s.data.sanitize(); n > 0 {
		_ = s.save()
	}
	return s, nil
}

// sanitize drops invalid ip_cidr entries from IPs and Devices; returns the count
// removed.
func (r *Rules) sanitize() int {
	removed := 0
	keep := func(list []string) []string {
		out := list[:0:0]
		for _, x := range list {
			if validCIDR(x) {
				out = append(out, x)
			} else {
				removed++
			}
		}
		return out
	}
	r.IPs = keep(r.IPs)
	r.Devices = keep(r.Devices)
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

// Get returns a copy of the current rules.
func (s *Store) Get() Rules {
	s.mu.Lock()
	defer s.mu.Unlock()
	return snapshot(s.data)
}

func snapshot(r Rules) Rules {
	return Rules{
		Domains:   append([]string(nil), r.Domains...),
		IPs:       append([]string(nil), r.IPs...),
		Processes: append([]string(nil), r.Processes...),
		Devices:   append([]string(nil), r.Devices...),
	}
}

// Set replaces the whole allow-list (used when activating a profile) and
// persists.
func (s *Store) Set(r Rules) (Rules, error) {
	return s.mutate(func() { s.data = snapshot(r) })
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
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" || strings.ContainsAny(d, "/ \t") {
		return s.Get(), fmt.Errorf("invalid domain: %q", d)
	}
	// A pattern with no literal label chars (e.g. "*", "*.*") would allow ~all
	// egress and defeat default-deny — reject it.
	if strings.Trim(d, "*?.") == "" {
		return s.Get(), fmt.Errorf("domain pattern too broad: %q", d)
	}
	return s.mutate(func() { s.data.Domains = add(s.data.Domains, d) })
}
func (s *Store) RemoveDomain(d string) (Rules, error) {
	return s.mutate(func() { s.data.Domains = remove(s.data.Domains, d) })
}
func (s *Store) AddIP(ip string) (Rules, error) {
	ip = strings.TrimSpace(ip)
	if !validCIDR(ip) {
		return s.Get(), fmt.Errorf("invalid ip/cidr: %q (use an IP or CIDR, not a domain)", ip)
	}
	return s.mutate(func() { s.data.IPs = add(s.data.IPs, ip) })
}
func (s *Store) RemoveIP(ip string) (Rules, error) {
	return s.mutate(func() { s.data.IPs = remove(s.data.IPs, ip) })
}
func (s *Store) AddProcess(p string) (Rules, error) {
	if p = strings.TrimSpace(p); p == "" {
		return s.Get(), fmt.Errorf("empty process")
	}
	return s.mutate(func() { s.data.Processes = add(s.data.Processes, p) })
}
func (s *Store) RemoveProcess(p string) (Rules, error) {
	return s.mutate(func() { s.data.Processes = remove(s.data.Processes, p) })
}
func (s *Store) AddDevice(ip string) (Rules, error) {
	ip = strings.TrimSpace(ip)
	if !validCIDR(ip) {
		return s.Get(), fmt.Errorf("invalid device ip/cidr: %q", ip)
	}
	return s.mutate(func() { s.data.Devices = add(s.data.Devices, ip) })
}
func (s *Store) RemoveDevice(ip string) (Rules, error) {
	return s.mutate(func() { s.data.Devices = remove(s.data.Devices, ip) })
}

func (s *Store) mutate(fn func()) (Rules, error) {
	s.mu.Lock()
	fn()
	snap := snapshot(s.data)
	err := s.save()
	s.mu.Unlock()
	return snap, err
}
