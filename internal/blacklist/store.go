// Package blacklist persists the egress deny-list (domains + keywords + regexes
// + IP CIDRs) that the gateway injects as reject rules ABOVE the allows, so a
// blacklisted destination is dropped even if it is otherwise whitelisted.
package blacklist

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
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

// Rules is the deny-list snapshot.
//   - Domains: matched as domain_suffix (reject).
//   - Keywords: matched as domain_keyword (reject on substring).
//   - Regexes: matched as domain_regex (each must compile).
//   - IPs: matched as ip_cidr (reject).
type Rules struct {
	Domains  []string `json:"domains"`
	Keywords []string `json:"keywords"`
	Regexes  []string `json:"regexes"`
	IPs      []string `json:"ips"`
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
	r.IPs = filter(r.IPs, validCIDR, &removed)
	r.Regexes = filter(r.Regexes, func(s string) bool {
		_, err := regexp.Compile(s)
		return err == nil
	}, &removed)
	return removed
}

func filter(list []string, keep func(string) bool, removed *int) []string {
	out := list[:0:0]
	for _, x := range list {
		if keep(x) {
			out = append(out, x)
		} else {
			*removed++
		}
	}
	return out
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
		Domains:  append([]string(nil), r.Domains...),
		Keywords: append([]string(nil), r.Keywords...),
		Regexes:  append([]string(nil), r.Regexes...),
		IPs:      append([]string(nil), r.IPs...),
	}
}

// Set replaces the whole deny-list and persists.
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

// AddDomain / RemoveDomain / AddKeyword / ... mutate and persist, returning the
// new snapshot. Validation errors leave the store unchanged.
func (s *Store) AddDomain(d string) (Rules, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" || strings.ContainsAny(d, "/ \t") {
		return s.Get(), fmt.Errorf("invalid domain: %q", d)
	}
	return s.mutate(func() { s.data.Domains = add(s.data.Domains, d) })
}
func (s *Store) RemoveDomain(d string) (Rules, error) {
	return s.mutate(func() { s.data.Domains = remove(s.data.Domains, d) })
}
func (s *Store) AddKeyword(k string) (Rules, error) {
	k = strings.ToLower(strings.TrimSpace(k))
	if k == "" {
		return s.Get(), fmt.Errorf("empty keyword")
	}
	return s.mutate(func() { s.data.Keywords = add(s.data.Keywords, k) })
}
func (s *Store) RemoveKeyword(k string) (Rules, error) {
	return s.mutate(func() { s.data.Keywords = remove(s.data.Keywords, k) })
}
func (s *Store) AddRegex(re string) (Rules, error) {
	re = strings.TrimSpace(re)
	if re == "" {
		return s.Get(), fmt.Errorf("empty regex")
	}
	if _, err := regexp.Compile(re); err != nil {
		return s.Get(), fmt.Errorf("invalid regex %q: %w", re, err)
	}
	return s.mutate(func() { s.data.Regexes = add(s.data.Regexes, re) })
}
func (s *Store) RemoveRegex(re string) (Rules, error) {
	return s.mutate(func() { s.data.Regexes = remove(s.data.Regexes, re) })
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

func (s *Store) mutate(fn func()) (Rules, error) {
	s.mu.Lock()
	fn()
	snap := snapshot(s.data)
	err := s.save()
	s.mu.Unlock()
	return snap, err
}
