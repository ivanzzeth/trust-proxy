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
//   - Notes: optional remarks keyed as "<dim>:<value>" (informational only).
type Rules struct {
	Domains []string          `json:"domains"`
	IPs     []string          `json:"ips"`
	Notes   map[string]string `json:"notes,omitempty"`
	// PrivateDirect keeps the engine's built-in LAN/private/reserved bypass on
	// the Route axis. nil or true = on, which is what every existing store and
	// every default install means.
	//
	// Turning it off is for the one deployment where "LAN goes direct" is wrong:
	// a WireGuard / Tailscale exit that IS the other side of 10.0.0.0/8, where
	// the point of the tunnel is to carry those ranges. It moves private
	// destinations from "always direct" to "whatever Route says" — it does NOT
	// remove them from the Permit gate, so LAN is never blocked by flipping it.
	PrivateDirect *bool `json:"private_direct,omitempty"`
}

// BypassPrivate reports whether the built-in private/LAN ranges still belong on
// the Route axis as direct. Absent means yes.
func (r Rules) BypassPrivate() bool { return r.PrivateDirect == nil || *r.PrivateDirect }

// Store is a file-backed no-proxy list, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data Rules
}

// NewStore opens (or seeds) the store at path. A fresh store starts empty; the
// built-in private/reserved CIDRs are added by the gateway engine, not seeded
// here, so they can't be accidentally removed — only switched off as a whole
// via PrivateDirect.
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
	r.Notes = liststore.PruneNotes(r.Notes, "ip", r.IPs)
	r.Notes = liststore.PruneNotes(r.Notes, "domain", r.Domains)
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
	out := Rules{
		Domains: append([]string(nil), r.Domains...),
		IPs:     append([]string(nil), r.IPs...),
		Notes:   liststore.CloneNotes(r.Notes),
	}
	if r.PrivateDirect != nil {
		v := *r.PrivateDirect
		out.PrivateDirect = &v
	}
	return out
}

// Set replaces the whole no-proxy list and persists.
func (s *Store) Set(r Rules) (Rules, error) {
	return s.mutate(func() { s.data = snapshot(r) })
}

// SetPrivateDirect turns the built-in private/LAN Route bypass on or off.
func (s *Store) SetPrivateDirect(on bool) (Rules, error) {
	return s.mutate(func() { v := on; s.data.PrivateDirect = &v })
}

// AddDomain / RemoveDomain / AddIP / RemoveIP mutate and persist, returning the
// new snapshot. Validation errors leave the store unchanged. Optional note
// (variadic) sets/updates the remark; omit to leave an existing remark alone.
func (s *Store) AddDomain(d string, note ...string) (Rules, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" || strings.ContainsAny(d, "/ \t") {
		return s.Get(), fmt.Errorf("invalid domain: %q", d)
	}
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

func applyNote(notes *map[string]string, dim, value string, note []string) {
	if len(note) == 0 {
		return
	}
	*notes = liststore.SetNote(*notes, dim, value, note[0])
}

func (s *Store) mutate(fn func()) (Rules, error) {
	return liststore.Mutate(&s.mu, s.path, &s.data, fn, snapshot)
}
