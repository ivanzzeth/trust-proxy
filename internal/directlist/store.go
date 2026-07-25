// Package directlist persists the routing "no-proxy" (bypass) list: domains +
// IP CIDRs that, once permitted by some other means, egress DIRECT instead of
// through the proxy group.
//
// It is a ROUTING (L4) concern, deliberately separate from the whitelist (an
// ACL/Permit concern) and the blacklist (a hard-deny concern). Per the
// Permit⊥Route invariant, a directlist entry NEVER joins the L3 permit gate
// by itself — gateway.injectAllow builds route->direct rules from it but does
// not fold it into the allow-set. A destination must already be permitted
// (whitelist, a permit-role rule set, or a permit custom rule) for a
// directlist entry to have any effect; it only decides which egress permitted
// traffic takes, never whether traffic is permitted.
package directlist

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/ivanzzeth/trust-proxy/internal/liststore"
)

// Rules is the no-proxy snapshot.
//   - Domains: matched as domain_suffix (+ domain_regex for globs) -> direct.
//   - IPs: matched as ip_cidr -> direct.
type Rules struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
}

// Store is a file-backed no-proxy list, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data Rules
}

// NewStore opens (or seeds) the store at path. A fresh store starts empty; the
// built-in private/reserved CIDRs are added by the gateway engine, not seeded
// here, so they can't be accidentally removed.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = Rules{}
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	// Drop entries that would make the box fail to build (bad CIDR), so a
	// poisoned store self-heals instead of bricking the gateway.
	if n := s.data.sanitize(); n > 0 {
		_ = s.save()
	}
	return s, nil
}

// sanitize drops invalid ip_cidr entries from IPs; returns the count removed.
func (r *Rules) sanitize() int {
	removed := 0
	r.IPs = liststore.Filter(r.IPs, liststore.ValidCIDR, &removed)
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
		Domains: append([]string(nil), r.Domains...),
		IPs:     append([]string(nil), r.IPs...),
	}
}

// Set replaces the whole no-proxy list and persists.
func (s *Store) Set(r Rules) (Rules, error) {
	return s.mutate(func() { s.data = snapshot(r) })
}

// AddDomain / RemoveDomain / AddIP / RemoveIP mutate and persist, returning the
// new snapshot. Validation errors leave the store unchanged.
func (s *Store) AddDomain(d string) (Rules, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" || strings.ContainsAny(d, "/ \t") {
		return s.Get(), fmt.Errorf("invalid domain: %q", d)
	}
	if strings.Trim(d, "*?.") == "" {
		return s.Get(), fmt.Errorf("domain pattern too broad: %q", d)
	}
	return s.mutate(func() { s.data.Domains = liststore.Add(s.data.Domains, d) })
}
func (s *Store) RemoveDomain(d string) (Rules, error) {
	return s.mutate(func() { s.data.Domains = liststore.Remove(s.data.Domains, d) })
}
func (s *Store) AddIP(ip string) (Rules, error) {
	ip = strings.TrimSpace(ip)
	if !liststore.ValidCIDR(ip) {
		return s.Get(), fmt.Errorf("invalid ip/cidr: %q (use an IP or CIDR, not a domain)", ip)
	}
	return s.mutate(func() { s.data.IPs = liststore.Add(s.data.IPs, ip) })
}
func (s *Store) RemoveIP(ip string) (Rules, error) {
	return s.mutate(func() { s.data.IPs = liststore.Remove(s.data.IPs, ip) })
}

func (s *Store) mutate(fn func()) (Rules, error) {
	return liststore.Mutate(&s.mu, s.path, &s.data, fn, snapshot)
}
