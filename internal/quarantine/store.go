// Package quarantine holds destinations the gateway blocked by itself — a
// threat-intel hit, or an upload the exfil detector judged. It is deliberately
// NOT the deny list: deny is operator policy and lives in the posture slot, so
// switching Strict<->Split or activating a profile replaces it wholesale. A
// defensive block must not evaporate because an unrelated policy switch happened,
// and it must not silently become part of a profile the operator later exports.
//
// Entries carry why and when, and are released explicitly.
package quarantine

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Entry is one quarantined destination.
type Entry struct {
	Value  string `json:"value"`  // domain or IP/CIDR
	IsIP   bool   `json:"is_ip"`  // matched as an address rather than a name
	Reason string `json:"reason"` // why the gateway blocked it
	Time   string `json:"time"`   // RFC3339, when it was quarantined
}

// List is the persisted set.
type List struct {
	Entries []Entry `json:"entries"`
}

// Domains returns the quarantined domains (for route injection).
func (l List) Domains() []string {
	var out []string
	for _, e := range l.Entries {
		if !e.IsIP {
			out = append(out, e.Value)
		}
	}
	return out
}

// IPs returns the quarantined addresses as CIDRs (for route injection).
func (l List) IPs() []string {
	var out []string
	for _, e := range l.Entries {
		if e.IsIP {
			out = append(out, e.Value)
		}
	}
	return out
}

// Store is a file-backed quarantine list, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data List
	now  func() time.Time
}

// NewStore loads (creating) the list at path.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path, now: time.Now}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
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

// Get returns a snapshot.
func (s *Store) Get() List {
	s.mu.Lock()
	defer s.mu.Unlock()
	return List{Entries: append([]Entry(nil), s.data.Entries...)}
}

// Add quarantines a destination. Domain and ip may each be empty; re-adding an
// existing value refreshes nothing (the original reason and time are kept, so
// the record of first detection survives).
func (s *Store) Add(domain, ip, reason string) (List, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	ip = strings.TrimSpace(ip)
	if domain == "" && ip == "" {
		return s.Get(), fmt.Errorf("nothing to quarantine")
	}
	if ip != "" {
		norm, err := normalizeIP(ip)
		if err != nil {
			return s.Get(), err
		}
		ip = norm
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Format(time.RFC3339)
	for _, v := range []struct {
		val  string
		isIP bool
	}{{domain, false}, {ip, true}} {
		if v.val == "" || s.hasLocked(v.val, v.isIP) {
			continue
		}
		s.data.Entries = append(s.data.Entries, Entry{Value: v.val, IsIP: v.isIP, Reason: reason, Time: now})
	}
	err := s.save()
	return List{Entries: append([]Entry(nil), s.data.Entries...)}, err
}

// Release removes one entry (the operator saying "this was a false positive").
func (s *Store) Release(value string) (List, error) {
	value = strings.TrimSpace(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.data.Entries[:0:0]
	for _, e := range s.data.Entries {
		if strings.EqualFold(e.Value, value) {
			continue
		}
		kept = append(kept, e)
	}
	s.data.Entries = kept
	err := s.save()
	return List{Entries: append([]Entry(nil), s.data.Entries...)}, err
}

// Clear releases everything.
func (s *Store) Clear() (List, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Entries = nil
	err := s.save()
	return List{}, err
}

func (s *Store) hasLocked(value string, isIP bool) bool {
	for _, e := range s.data.Entries {
		if e.IsIP == isIP && strings.EqualFold(e.Value, value) {
			return true
		}
	}
	return false
}

// normalizeIP accepts an address or CIDR and returns a CIDR, so route rules can
// use it verbatim.
func normalizeIP(v string) (string, error) {
	if strings.Contains(v, "/") {
		if _, _, err := net.ParseCIDR(v); err != nil {
			return "", fmt.Errorf("invalid CIDR %q", v)
		}
		return v, nil
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", v)
	}
	if ip.To4() != nil {
		return v + "/32", nil
	}
	return v + "/128", nil
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}
