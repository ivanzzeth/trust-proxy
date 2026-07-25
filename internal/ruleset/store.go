// Package ruleset persists imported sing-box rule_sets and the role each plays
// on the Permit / Route / Deny axes (permit, route-direct, route-proxy, deny,
// or combined permit+route-* after migration). The gateway injects enabled
// sets into route.rule_set + route.rules on hot-reload.
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
		Tag: "geosite-cn", Name: "中国大陆域名 (route direct)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
		SuggestedRole: apitypes.RuleRoleRouteDirect,
	},
	{
		Tag: "geoip-cn", Name: "中国大陆 IP (route direct)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs",
		SuggestedRole: apitypes.RuleRoleRouteDirect,
	},
	{
		Tag: "geosite-geolocation-!cn", Name: "非中国大陆域名 (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-geolocation-!cn.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-google", Name: "Google (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-google.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-youtube", Name: "YouTube (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-youtube.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-youtube.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-github", Name: "GitHub (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-github.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-github.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-telegram", Name: "Telegram (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-telegram.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-telegram.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-slack", Name: "Slack (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-slack.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-slack.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-notion", Name: "Notion (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-notion.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-notion.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-microsoft-dev", Name: "Microsoft 开发者 (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-microsoft-dev.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-microsoft-dev.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-twitter", Name: "X / Twitter (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-twitter.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-twitter.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-netflix", Name: "Netflix (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-netflix.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-spotify", Name: "Spotify (permit+proxy)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-spotify.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-spotify.srs",
		SuggestedRole: apitypes.RuleRolePermitRouteProxy,
	},
	{
		Tag: "geosite-apple", Name: "Apple (route direct)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-apple.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-apple.srs",
		SuggestedRole: apitypes.RuleRoleRouteDirect,
	},
	{
		Tag: "geosite-category-ads-all", Name: "广告 / 追踪拦截 (deny)", Format: "binary",
		URL:           "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
		Mirror:        "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ads-all.srs",
		SuggestedRole: apitypes.RuleRoleDeny,
	},
}

// CatalogByTag returns a catalog entry by tag, or false if unknown.
func CatalogByTag(tag string) (apitypes.RuleSetCatalogEntry, bool) {
	for _, e := range Catalog {
		if e.Tag == tag {
			return e, true
		}
	}
	return apitypes.RuleSetCatalogEntry{}, false
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
	changed := s.migrateRoles()
	if s.data.sanitize() > 0 {
		changed = true
	}
	if changed {
		_ = s.save()
	}
	return s, nil
}

// migrateRoles rewrites legacy allow-*/block roles onto the orthogonal
// vocabulary (preserving prior allow+route behavior via permit+route-*).
func (s *Store) migrateRoles() bool {
	changed := false
	for i := range s.data.Sets {
		old := s.data.Sets[i].Role
		neu := apitypes.NormalizeRuleRole(old)
		if neu != old {
			s.data.Sets[i].Role = neu
			changed = true
		}
	}
	return changed
}

// sanitize disables (but doesn't delete — the tag/URL are still worth
// keeping visible for the user to fix) any set left with an unrecognized
// role after migrateRoles, so a poisoned store fails visibly-off rather than
// silently sitting inert with undefined gateway behavior. Returns the count
// changed.
func (r *Sets) sanitize() int {
	fixed := 0
	for i := range r.Sets {
		if r.Sets[i].Enabled && !apitypes.ValidRuleRole(r.Sets[i].Role) {
			r.Sets[i].Enabled = false
			fixed++
		}
	}
	return fixed
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

// Set replaces the whole collection and persists (used by profile activate).
func (s *Store) Set(sets Sets) (Sets, error) {
	if sets.Sets == nil {
		sets.Sets = []apitypes.RuleSet{}
	}
	return s.mutate(func() {
		s.data.Sets = append([]apitypes.RuleSet(nil), sets.Sets...)
	})
}

// Add inserts or overwrites (by Tag = idempotent re-import) and persists.
func (s *Store) Add(rs apitypes.RuleSet) (Sets, error) {
	if rs.Tag == "" {
		return s.Get(), fmt.Errorf("rule set tag is required")
	}
	if !apitypes.ValidRuleRole(rs.Role) {
		return s.Get(), fmt.Errorf("invalid role %q", rs.Role)
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
	if !apitypes.ValidRuleRole(role) {
		return s.Get(), fmt.Errorf("invalid role %q", role)
	}
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
