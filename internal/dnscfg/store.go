// Package dnscfg persists the resolver policy (DNS servers + split rules +
// strategy) that the gateway injects into sing-box's dns block. Routing DNS
// through the exit node (detour="proxy") prevents DNS leaks and is the
// prerequisite for DNS-tunnel / DGA detection (all queries pass through us).
package dnscfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

var validTypes = map[string]bool{"local": true, "udp": true, "tcp": true, "tls": true, "https": true, "quic": true, "fakeip": true, "hosts": true}
var validStrategy = map[string]bool{"": true, "prefer_ipv4": true, "prefer_ipv6": true, "ipv4_only": true, "ipv6_only": true}

// Default = system resolver only (non-disruptive; the user opts into
// proxy/split DNS from the console).
func defaultConfig() apitypes.DNSConfig {
	return apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{{Tag: "local", Type: "local"}},
		Rules:   []apitypes.DNSRule{},
		Final:   "local",
	}
}

// Store is a file-backed DNS config, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data apitypes.DNSConfig
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = defaultConfig()
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

// Get returns a snapshot.
func (s *Store) Get() apitypes.DNSConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.data)
}

// Set validates and replaces the whole config.
func (s *Store) Set(c apitypes.DNSConfig) (apitypes.DNSConfig, error) {
	if err := validate(c); err != nil {
		return s.Get(), err
	}
	s.mu.Lock()
	s.data = clone(c)
	err := s.save()
	s.mu.Unlock()
	return s.Get(), err
}

func validate(c apitypes.DNSConfig) error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("at least one DNS server is required")
	}
	if !validStrategy[c.Strategy] {
		return fmt.Errorf("invalid strategy %q", c.Strategy)
	}
	tags := map[string]bool{}
	for _, sv := range c.Servers {
		if sv.Tag == "" {
			return fmt.Errorf("server tag is required")
		}
		if tags[sv.Tag] {
			return fmt.Errorf("duplicate server tag %q", sv.Tag)
		}
		tags[sv.Tag] = true
		if !validTypes[sv.Type] {
			return fmt.Errorf("invalid server type %q (want local|udp|tcp|tls|https|quic|fakeip|hosts)", sv.Type)
		}
		// fakeip/hosts synthesize answers locally — no server address or detour.
		if sv.Type != "local" && sv.Type != "fakeip" && sv.Type != "hosts" && sv.Server == "" {
			return fmt.Errorf("server %q: address required for type %s", sv.Tag, sv.Type)
		}
		if sv.Detour != "" && sv.Detour != "direct" && sv.Detour != "proxy" {
			return fmt.Errorf("server %q: detour must be direct or proxy", sv.Tag)
		}
	}
	for _, r := range c.Rules {
		if !tags[r.Server] {
			return fmt.Errorf("rule references unknown server %q", r.Server)
		}
		if len(r.DomainSuffix) == 0 && len(r.RuleSet) == 0 {
			return fmt.Errorf("rule for server %q has no matcher", r.Server)
		}
	}
	if c.Final != "" && !tags[c.Final] {
		return fmt.Errorf("final references unknown server %q", c.Final)
	}
	return nil
}

func clone(c apitypes.DNSConfig) apitypes.DNSConfig {
	out := apitypes.DNSConfig{Final: c.Final, Strategy: c.Strategy}
	out.Servers = make([]apitypes.DNSServer, 0, len(c.Servers))
	for _, sv := range c.Servers {
		if sv.Records != nil {
			rec := make(map[string][]string, len(sv.Records))
			for h, ips := range sv.Records {
				rec[h] = append([]string(nil), ips...)
			}
			sv.Records = rec
		}
		out.Servers = append(out.Servers, sv)
	}
	out.Rules = make([]apitypes.DNSRule, 0, len(c.Rules))
	for _, r := range c.Rules {
		out.Rules = append(out.Rules, apitypes.DNSRule{
			DomainSuffix: append([]string(nil), r.DomainSuffix...),
			RuleSet:      append([]string(nil), r.RuleSet...),
			Server:       r.Server,
		})
	}
	return out
}
