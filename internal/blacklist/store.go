// Package blacklist persists the egress deny-list (domains + keywords + regexes
// + IP CIDRs) that the gateway injects as reject rules ABOVE the allows, so a
// blacklisted destination is dropped even if it is otherwise whitelisted.
package blacklist

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/ivanzzeth/trust-proxy/internal/liststore"
)

// Rules is the deny-list snapshot.
//   - Domains: matched as domain_suffix (reject).
//   - Keywords: matched as domain_keyword (reject on substring).
//   - Regexes: matched as domain_regex (each must compile).
//   - IPs: matched as ip_cidr (reject).
//   - Notes: optional remarks keyed as "<dim>:<value>" (informational only).
type Rules struct {
	Domains  []string          `json:"domains"`
	Keywords []string          `json:"keywords"`
	Regexes  []string          `json:"regexes"`
	IPs      []string          `json:"ips"`
	Notes    map[string]string `json:"notes,omitempty"`
}

// Store is a file-backed deny-list, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data Rules
}

// NewStore opens (or seeds) the store at path. A fresh store starts empty (the
// deny-list only adds rejections on top of the default-deny allow model).
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
	// Drop entries that would make the box fail to build (bad CIDR, uncompilable
	// regex), so a poisoned store self-heals instead of bricking the gateway.
	if n := s.data.sanitize(); n > 0 {
		_ = s.save()
	}
	return s, nil
}

// sanitize drops invalid ip_cidr entries from IPs and uncompilable regexes;
// returns the count removed.
func (r *Rules) sanitize() int {
	removed := 0
	r.IPs = liststore.Filter(r.IPs, liststore.ValidCIDR, &removed)
	r.Regexes = liststore.Filter(r.Regexes, func(s string) bool {
		_, err := regexp.Compile(s)
		return err == nil
	}, &removed)
	r.Notes = liststore.PruneNotes(r.Notes, "ip", r.IPs)
	r.Notes = liststore.PruneNotes(r.Notes, "regex", r.Regexes)
	r.Notes = liststore.PruneNotes(r.Notes, "domain", r.Domains)
	r.Notes = liststore.PruneNotes(r.Notes, "keyword", r.Keywords)
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
		Domains:  append([]string(nil), r.Domains...),
		Keywords: append([]string(nil), r.Keywords...),
		Regexes:  append([]string(nil), r.Regexes...),
		IPs:      append([]string(nil), r.IPs...),
		Notes:    liststore.CloneNotes(r.Notes),
	}
}

// Set replaces the whole deny-list and persists.
func (s *Store) Set(r Rules) (Rules, error) {
	return s.mutate(func() { s.data = snapshot(r) })
}

// AddDomain / RemoveDomain / AddKeyword / ... mutate and persist, returning the
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
func (s *Store) AddKeyword(k string, note ...string) (Rules, error) {
	k = strings.ToLower(strings.TrimSpace(k))
	if k == "" {
		return s.Get(), fmt.Errorf("empty keyword")
	}
	return s.mutate(func() {
		s.data.Keywords = liststore.Add(s.data.Keywords, k)
		applyNote(&s.data.Notes, "keyword", k, note)
	})
}
func (s *Store) RemoveKeyword(k string) (Rules, error) {
	return s.mutate(func() {
		s.data.Keywords = liststore.Remove(s.data.Keywords, k)
		s.data.Notes = liststore.ClearNote(s.data.Notes, "keyword", k)
	})
}
func (s *Store) AddRegex(re string, note ...string) (Rules, error) {
	re = strings.TrimSpace(re)
	if re == "" {
		return s.Get(), fmt.Errorf("empty regex")
	}
	if _, err := regexp.Compile(re); err != nil {
		return s.Get(), fmt.Errorf("invalid regex %q: %w", re, err)
	}
	return s.mutate(func() {
		s.data.Regexes = liststore.Add(s.data.Regexes, re)
		applyNote(&s.data.Notes, "regex", re, note)
	})
}
func (s *Store) RemoveRegex(re string) (Rules, error) {
	return s.mutate(func() {
		s.data.Regexes = liststore.Remove(s.data.Regexes, re)
		s.data.Notes = liststore.ClearNote(s.data.Notes, "regex", re)
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
