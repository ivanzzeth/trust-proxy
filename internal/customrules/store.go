// Package customrules persists ordered policy rules on the Permit and/or Route
// axes. Each rule has a matcher plus optional Permit (L3) and Egress (L4).
// Order is priority for routing (first-match). The gateway injects enabled
// rules: permit matchers join the ACL allow-set; egress emits route rules
// above rule-set egress. Route never opens the gate by itself.
package customrules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Rules is the persisted, ordered collection snapshot.
type Rules struct {
	Rules []apitypes.CustomRule `json:"rules"`
}

// SingboxMatchKey maps our match kind to the sing-box route-rule matcher key.
func SingboxMatchKey(match string) (string, bool) {
	switch match {
	case apitypes.CustomMatchDomain:
		return "domain", true
	case apitypes.CustomMatchDomainSuffix:
		return "domain_suffix", true
	case apitypes.CustomMatchKeyword:
		return "domain_keyword", true
	case apitypes.CustomMatchRegex:
		return "domain_regex", true
	case apitypes.CustomMatchIPCIDR:
		return "ip_cidr", true
	default:
		return "", false
	}
}

func validEgress(a string) bool {
	switch a {
	case apitypes.CustomEgressDirect, apitypes.CustomEgressProxy, apitypes.CustomEgressBlock,
		apitypes.CustomEgressNode, apitypes.CustomEgressNone, "":
		return true
	}
	return false
}

// validate normalizes and checks a rule; returns an error if it can't be a
// valid policy rule.
func validate(r *apitypes.CustomRule) error {
	apitypes.NormalizeCustomRule(r)
	r.Match = strings.TrimSpace(r.Match)
	r.Value = strings.TrimSpace(r.Value)
	r.Action = strings.TrimSpace(r.Action)
	r.Egress = strings.TrimSpace(r.Egress)
	r.Node = strings.TrimSpace(r.Node)
	r.Pack = strings.TrimSpace(r.Pack)
	if _, ok := SingboxMatchKey(r.Match); !ok {
		return fmt.Errorf("invalid match kind %q", r.Match)
	}
	if r.Value == "" {
		return fmt.Errorf("value is required")
	}
	eg := r.RouteEgress()
	if r.Egress != "" && !validEgress(r.Egress) {
		return fmt.Errorf("invalid egress %q", r.Egress)
	}
	if r.Action != "" && !validEgress(r.Action) && r.Action != apitypes.CustomEgressNone {
		return fmt.Errorf("invalid action %q", r.Action)
	}
	// Must grant permit and/or select an egress (block counts as egress).
	if !r.GrantsPermit() && eg == "" {
		return fmt.Errorf("rule must set permit and/or egress")
	}
	if eg == apitypes.CustomEgressNode && r.Node == "" {
		return fmt.Errorf("egress %q requires a target", eg)
	}
	if eg != apitypes.CustomEgressNode && eg != apitypes.CustomEgressProxy {
		r.Node = ""
	}
	switch r.Match {
	case apitypes.CustomMatchIPCIDR:
		if !validCIDR(r.Value) {
			return fmt.Errorf("invalid ip/cidr: %q", r.Value)
		}
	case apitypes.CustomMatchRegex:
		if _, err := regexp.Compile(r.Value); err != nil {
			return fmt.Errorf("invalid regex %q: %w", r.Value, err)
		}
	case apitypes.CustomMatchDomain, apitypes.CustomMatchDomainSuffix:
		r.Value = strings.ToLower(r.Value)
		if strings.ContainsAny(r.Value, " \t") {
			return fmt.Errorf("invalid domain: %q", r.Value)
		}
	}
	return nil
}

func validCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}

func idFor(r apitypes.CustomRule) string {
	eg := r.RouteEgress()
	if eg == "" {
		eg = r.Egress
	}
	permit := "0"
	if r.GrantsPermit() {
		permit = "1"
	}
	sum := sha256.Sum256([]byte(r.Match + "|" + r.Value + "|" + eg + "|" + r.Node + "|" + permit))
	return hex.EncodeToString(sum[:])[:12]
}

// Store is a file-backed, ordered collection of custom routing rules.
type Store struct {
	path string
	mu   sync.Mutex
	data Rules
}

// NewStore opens (or seeds an empty) store at path. Invalid rules are dropped on
// load (self-heal) so a poisoned store can't brick the gateway.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = Rules{Rules: []apitypes.CustomRule{}}
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	if s.data.Rules == nil {
		s.data.Rules = []apitypes.CustomRule{}
	}
	if n := s.sanitize(); n > 0 {
		_ = s.save()
	}
	return s, nil
}

// sanitize drops rules that fail validation; returns the count removed.
func (s *Store) sanitize() int {
	removed := 0
	out := s.data.Rules[:0:0]
	for _, r := range s.data.Rules {
		if err := validate(&r); err != nil {
			removed++
			continue
		}
		if r.ID == "" {
			r.ID = idFor(r)
		}
		out = append(out, r)
	}
	s.data.Rules = out
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

// Get returns a deep-copy snapshot (Rules never nil, so it serializes as []).
func (s *Store) Get() Rules {
	s.mu.Lock()
	defer s.mu.Unlock()
	return snapshot(s.data)
}

func snapshot(r Rules) Rules {
	return Rules{Rules: append(make([]apitypes.CustomRule, 0, len(r.Rules)), r.Rules...)}
}

// Set replaces the whole ordered collection and persists (used for rollback).
func (s *Store) Set(r Rules) (Rules, error) {
	return s.mutate(func() { s.data = snapshot(r) })
}

// Add appends a validated rule (idempotent by ID = same match+value+action+node
// overwrites in place) and persists.
func (s *Store) Add(r apitypes.CustomRule) (Rules, error) {
	if err := validate(&r); err != nil {
		return s.Get(), err
	}
	r.ID = idFor(r)
	return s.mutate(func() {
		for i := range s.data.Rules {
			if s.data.Rules[i].ID == r.ID {
				s.data.Rules[i] = r
				return
			}
		}
		s.data.Rules = append(s.data.Rules, r)
	})
}

// Update applies a partial patch to the rule with id, revalidates, and persists.
// If the change alters the identity fields, the ID is recomputed.
func (s *Store) Update(id string, p apitypes.PatchCustomRuleRequest) (Rules, error) {
	s.mu.Lock()
	idx := -1
	for i := range s.data.Rules {
		if s.data.Rules[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.mu.Unlock()
		return s.Get(), fmt.Errorf("rule %q not found", id)
	}
	r := s.data.Rules[idx]
	if p.Enabled != nil {
		r.Enabled = *p.Enabled
	}
	if p.Match != nil {
		r.Match = *p.Match
	}
	if p.Value != nil {
		r.Value = *p.Value
	}
	if p.Action != nil {
		r.Action = *p.Action
		r.Egress = *p.Action
	}
	if p.Egress != nil {
		r.Egress = *p.Egress
		if *p.Egress != apitypes.CustomEgressNone {
			r.Action = *p.Egress
		}
	}
	if p.Permit != nil {
		r.Permit = p.Permit
	}
	if p.Node != nil {
		r.Node = *p.Node
	}
	if p.Pack != nil {
		r.Pack = *p.Pack
	}
	if err := validate(&r); err != nil {
		s.mu.Unlock()
		return s.Get(), err
	}
	r.ID = idFor(r)
	s.data.Rules[idx] = r
	snap := snapshot(s.data)
	err := s.save()
	s.mu.Unlock()
	return snap, err
}

// Remove deletes the rule with the given id.
func (s *Store) Remove(id string) (Rules, error) {
	return s.mutate(func() {
		out := s.data.Rules[:0:0]
		for _, x := range s.data.Rules {
			if x.ID != id {
				out = append(out, x)
			}
		}
		s.data.Rules = out
	})
}

// SetEnabled toggles a single rule.
func (s *Store) SetEnabled(id string, enabled bool) (Rules, error) {
	return s.mutate(func() {
		for i := range s.data.Rules {
			if s.data.Rules[i].ID == id {
				s.data.Rules[i].Enabled = enabled
			}
		}
	})
}

// SetPackEnabled toggles every rule in the named Allow pack at once.
func (s *Store) SetPackEnabled(pack string, enabled bool) (Rules, error) {
	return s.mutate(func() {
		for i := range s.data.Rules {
			if s.data.Rules[i].Pack == pack {
				s.data.Rules[i].Enabled = enabled
			}
		}
	})
}

// RemovePack deletes every rule in the named Allow pack.
func (s *Store) RemovePack(pack string) (Rules, error) {
	return s.mutate(func() {
		out := s.data.Rules[:0:0]
		for _, x := range s.data.Rules {
			if x.Pack != pack {
				out = append(out, x)
			}
		}
		s.data.Rules = out
	})
}

// ReplacePack atomically drops every rule tagged with pack, then appends the
// supplied rules (tagged + enabled). Re-importing a preset overwrites without
// leaving stale matchers from an older pack version.
func (s *Store) ReplacePack(pack string, rules []apitypes.CustomRule) (Rules, error) {
	if pack == "" {
		return s.Get(), fmt.Errorf("pack name is required")
	}
	prepared := make([]apitypes.CustomRule, 0, len(rules))
	for _, r := range rules {
		r.Pack = pack
		r.Enabled = true
		if err := validate(&r); err != nil {
			return s.Get(), err
		}
		r.ID = idFor(r)
		prepared = append(prepared, r)
	}
	return s.mutate(func() {
		out := make([]apitypes.CustomRule, 0, len(s.data.Rules))
		for _, x := range s.data.Rules {
			if x.Pack != pack {
				out = append(out, x)
			}
		}
		s.data.Rules = append(out, prepared...)
	})
}

// Move shifts the rule up (dir<0) or down (dir>0) by one position, changing its
// first-match priority. Out-of-range moves are no-ops.
func (s *Store) Move(id string, dir int) (Rules, error) {
	return s.mutate(func() {
		idx := -1
		for i := range s.data.Rules {
			if s.data.Rules[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return
		}
		j := idx + 1
		if dir < 0 {
			j = idx - 1
		}
		if j < 0 || j >= len(s.data.Rules) {
			return
		}
		s.data.Rules[idx], s.data.Rules[j] = s.data.Rules[j], s.data.Rules[idx]
	})
}

func (s *Store) mutate(fn func()) (Rules, error) {
	s.mu.Lock()
	fn()
	snap := snapshot(s.data)
	err := s.save()
	s.mu.Unlock()
	return snap, err
}
