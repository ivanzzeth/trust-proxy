// Package whitelist persists the egress allow-list (domains + IP CIDRs) that
// the gateway injects into its route rules. Default-deny: only these egress.
package whitelist

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/ivanzzeth/trust-proxy/internal/liststore"
)

// Rules is the allow-list snapshot.
//   - Domains / IPs: allowed egress destinations (default-deny for the rest).
//   - Processes: OPT-IN process allow-list — when non-empty, any process NOT
//     listed is rejected (unknown binaries can't egress). Path-separator entries
//     match process_path, others process_name.
//   - Devices: OPT-IN source (device) allow-list — when non-empty, any source
//     IP/CIDR NOT listed is rejected (only known devices may egress; for
//     gateway/router deployments). Entries are IPs or CIDRs (source_ip_cidr).
//   - Notes: optional remarks keyed as "<dim>:<value>" (domain:…, ip:…, …).
//     Purely informational — the data plane never reads them.
type Rules struct {
	Domains   []string          `json:"domains"`
	IPs       []string          `json:"ips"`
	Processes []string          `json:"processes"`
	Devices   []string          `json:"devices"`
	Notes     map[string]string `json:"notes,omitempty"`
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
	r.IPs = liststore.Filter(r.IPs, liststore.ValidCIDR, &removed)
	r.Devices = liststore.Filter(r.Devices, liststore.ValidCIDR, &removed)
	r.Notes = liststore.PruneNotes(r.Notes, "ip", r.IPs)
	r.Notes = liststore.PruneNotes(r.Notes, "device", r.Devices)
	r.Notes = liststore.PruneNotes(r.Notes, "domain", r.Domains)
	r.Notes = liststore.PruneNotes(r.Notes, "process", r.Processes)
	return removed
}

func (s *Store) save() error { return liststore.SaveJSON(s.path, s.data) }

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
		Notes:     liststore.CloneNotes(r.Notes),
	}
}

// Set replaces the whole allow-list (used when activating a profile) and
// persists.
func (s *Store) Set(r Rules) (Rules, error) {
	return s.mutate(func() { s.data = snapshot(r) })
}

// AddDomain / RemoveDomain / AddIP / … mutate and persist, returning the new
// snapshot. Optional note (variadic, at most one) sets/updates the remark;
// omit it to leave an existing remark alone on re-add. An explicit empty
// string clears the remark.
func (s *Store) AddDomain(d string, note ...string) (Rules, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" || strings.ContainsAny(d, "/ \t") {
		return s.Get(), fmt.Errorf("invalid domain: %q", d)
	}
	// A pattern with no literal label chars (e.g. "*", "*.*") would allow ~all
	// egress and defeat default-deny — reject it.
	if strings.Trim(d, "*?.") == "" {
		return s.Get(), fmt.Errorf("domain pattern too broad: %q", d)
	}
	return s.mutate(func() {
		s.data.Domains = liststore.Add(s.data.Domains, d)
		applyNote(&s.data.Notes, "domain", d, note)
	})
}
func (s *Store) RemoveDomain(d string) (Rules, error) {
	return s.mutate(func() {
		s.data.Domains = liststore.Remove(s.data.Domains, d)
		s.data.Notes = liststore.ClearNote(s.data.Notes, "domain", d)
	})
}
func (s *Store) AddIP(ip string, note ...string) (Rules, error) {
	ip = strings.TrimSpace(ip)
	if !liststore.ValidCIDR(ip) {
		return s.Get(), fmt.Errorf("invalid ip/cidr: %q (use an IP or CIDR, not a domain)", ip)
	}
	return s.mutate(func() {
		s.data.IPs = liststore.Add(s.data.IPs, ip)
		applyNote(&s.data.Notes, "ip", ip, note)
	})
}
func (s *Store) RemoveIP(ip string) (Rules, error) {
	return s.mutate(func() {
		s.data.IPs = liststore.Remove(s.data.IPs, ip)
		s.data.Notes = liststore.ClearNote(s.data.Notes, "ip", ip)
	})
}
func (s *Store) AddProcess(p string, note ...string) (Rules, error) {
	if p = strings.TrimSpace(p); p == "" {
		return s.Get(), fmt.Errorf("empty process")
	}
	return s.mutate(func() {
		s.data.Processes = liststore.Add(s.data.Processes, p)
		applyNote(&s.data.Notes, "process", p, note)
	})
}
func (s *Store) RemoveProcess(p string) (Rules, error) {
	return s.mutate(func() {
		s.data.Processes = liststore.Remove(s.data.Processes, p)
		s.data.Notes = liststore.ClearNote(s.data.Notes, "process", p)
	})
}
func (s *Store) AddDevice(ip string, note ...string) (Rules, error) {
	ip = strings.TrimSpace(ip)
	if !liststore.ValidCIDR(ip) {
		return s.Get(), fmt.Errorf("invalid device ip/cidr: %q", ip)
	}
	return s.mutate(func() {
		s.data.Devices = liststore.Add(s.data.Devices, ip)
		applyNote(&s.data.Notes, "device", ip, note)
	})
}
func (s *Store) RemoveDevice(ip string) (Rules, error) {
	return s.mutate(func() {
		s.data.Devices = liststore.Remove(s.data.Devices, ip)
		s.data.Notes = liststore.ClearNote(s.data.Notes, "device", ip)
	})
}

func applyNote(notes *map[string]string, dim, value string, note []string) {
	if len(note) == 0 {
		return
	}
	*notes = liststore.SetNote(*notes, dim, value, note[0])
}

func (s *Store) mutate(fn func()) (Rules, error) {
	return liststore.Mutate(&s.mu, s.path, &s.data, fn, snapshot)
}
