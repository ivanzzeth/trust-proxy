// Package ruleset persists imported sing-box rule_sets (remote .srs/.json or
// local files) and the role each plays in the gateway's default-deny route
// (block / allow-direct / allow-proxy). The gateway injects enabled sets into
// route.rule_set + route.rules on hot-reload.
package ruleset

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Sets is the persisted collection snapshot.
type Sets struct {
	Sets []apitypes.RuleSet `json:"sets"`
}

// Catalog is a curated set of one-click importable public rule sets. Not
// persisted; served to the console so users can import without knowing URLs.
// Primary URLs are raw.githubusercontent; mirrors are jsdelivr (usable where
// GitHub is blocked — relevant since download_detour is always "direct").
var Catalog = []apitypes.RuleSetCatalogEntry{
	{
		Tag: "geosite-cn", Name: "中国大陆域名 (CN direct)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
		SuggestedRole: apitypes.RuleRoleAllowDirect,
	},
	{
		Tag: "geoip-cn", Name: "中国大陆 IP (CN direct)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs",
		SuggestedRole: apitypes.RuleRoleAllowDirect,
	},
	{
		Tag: "geosite-geolocation-!cn", Name: "非中国大陆域名 (proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-geolocation-!cn.srs",
		SuggestedRole: apitypes.RuleRoleAllowProxy,
	},
	{
		Tag: "geosite-category-ads-all", Name: "广告 / 追踪拦截 (block)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ads-all.srs",
		SuggestedRole: apitypes.RuleRoleBlock,
	},
}

// Store is a file-backed rule-set collection, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data Sets
}

// NewStore opens (or seeds an empty) store at path.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = Sets{Sets: []apitypes.RuleSet{}}
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

// Get returns a deep-copy snapshot (Sets never nil, so it serializes as []).
func (s *Store) Get() Sets {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Sets{Sets: append(make([]apitypes.RuleSet, 0, len(s.data.Sets)), s.data.Sets...)}
}

// Add inserts or overwrites (by Tag = idempotent re-import) and persists.
func (s *Store) Add(rs apitypes.RuleSet) (Sets, error) {
	if rs.Tag == "" {
		return s.Get(), fmt.Errorf("rule set tag is required")
	}
	if rs.DownloadDetour == "" {
		rs.DownloadDetour = "direct"
	}
	if rs.UpdateInterval == "" {
		rs.UpdateInterval = "1d"
	}
	return s.mutate(func() {
		for i := range s.data.Sets {
			if s.data.Sets[i].Tag == rs.Tag {
				s.data.Sets[i] = rs
				return
			}
		}
		s.data.Sets = append(s.data.Sets, rs)
	})
}

// Remove deletes the set with the given tag.
func (s *Store) Remove(tag string) (Sets, error) {
	return s.mutate(func() {
		out := s.data.Sets[:0:0]
		for _, x := range s.data.Sets {
			if x.Tag != tag {
				out = append(out, x)
			}
		}
		s.data.Sets = out
	})
}

// SetRole / SetEnabled patch a single set.
func (s *Store) SetRole(tag, role string) (Sets, error) {
	return s.mutate(func() {
		for i := range s.data.Sets {
			if s.data.Sets[i].Tag == tag {
				s.data.Sets[i].Role = role
			}
		}
	})
}

func (s *Store) SetEnabled(tag string, enabled bool) (Sets, error) {
	return s.mutate(func() {
		for i := range s.data.Sets {
			if s.data.Sets[i].Tag == tag {
				s.data.Sets[i].Enabled = enabled
			}
		}
	})
}

func (s *Store) mutate(fn func()) (Sets, error) {
	s.mu.Lock()
	fn()
	snap := Sets{Sets: append([]apitypes.RuleSet(nil), s.data.Sets...)}
	err := s.save()
	s.mu.Unlock()
	return snap, err
}
