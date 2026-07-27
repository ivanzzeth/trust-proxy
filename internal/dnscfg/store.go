// Package dnscfg persists the resolver policy (DNS servers + split rules +
// strategy) that the gateway injects into sing-box's dns block. Routing DNS
// through the exit node (detour="proxy") prevents DNS leaks and is the
// prerequisite for DNS-tunnel / DGA detection (all queries pass through us).
package dnscfg

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

var validTypes = map[string]bool{"local": true, "udp": true, "tcp": true, "tls": true, "https": true, "quic": true, "fakeip": true, "hosts": true}

// reservedDirectTag mirrors gateway's synthesized direct-resolver tag. Kept as a
// literal (not an import) so the store has no dependency on the gateway.
const reservedDirectTag = "dns-direct"

var validStrategy = map[string]bool{"": true, "prefer_ipv4": true, "prefer_ipv6": true, "ipv4_only": true, "ipv6_only": true}

// Default: resolve through an encrypted resolver behind the exit, and let
// injectDirectDNS send direct-routed domains to a domestic one.
//
// The old default was the system resolver alone, which is the one shape that
// satisfies none of this package's reasons for existing: every domain you then
// proxy is still queried in the clear against whatever the OS points at, so the
// ISP sees the lot, and a censored domain answers with a poisoned address that
// gets dialed through the exit and fails. It also meant injectDirectDNS — the
// entire "DNS follows route" mechanism — never activated on a fresh install,
// because it only splits away from a resolver that sits behind the proxy.
//
// Two deliberate omissions:
//
//   - no `rule_set` DNS rule (the console's China-split preset has one for
//     geosite-cn). A fresh install has no rule sets, so the reference would
//     dangle and the box would refuse to start — the exact class of bug that
//     shipped once already. It is unnecessary anyway: injectDirectDNS mirrors
//     the *final* route table into dns.rules, so anything routed direct gets the
//     domestic resolver without naming a rule set here.
//   - `local` is kept as a server but is not final: something to fall back to by
//     hand on a network where 1.1.1.1 is unreachable.
//
// Bootstrapping is fine with no nodes yet: `detour: proxy` resolves to the proxy
// group, which is a selector over direct until an exit exists, and the server is
// an IP so there is no name to look up first.
func defaultConfig() apitypes.DNSConfig {
	return apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{
			{Tag: "local", Type: "local"},
			{Tag: "doh", Type: "https", Server: "1.1.1.1", Detour: "proxy"},
		},
		Rules: []apitypes.DNSRule{},
		Final: "doh",
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
		// Reserved: the gateway synthesizes this tag for the direct-route half of
		// the split (see apitypes.DNSConfig.DirectServer).
		if sv.Tag == reservedDirectTag {
			return fmt.Errorf("server tag %q is reserved (set direct_server instead)", reservedDirectTag)
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
	if err := validateDirectServer(c.DirectServer); err != nil {
		return err
	}
	return nil
}

// validateDirectServer accepts "", an IP, an ip:port, or a bare hostname — the
// resolver used for direct-routed domains (see apitypes.DNSConfig).
func validateDirectServer(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if net.ParseIP(strings.Trim(v, "[]")) != nil {
		return nil
	}
	if host, port, err := net.SplitHostPort(v); err == nil {
		n, cErr := strconv.Atoi(port)
		if host == "" || cErr != nil || n <= 0 || n > 65535 {
			return fmt.Errorf("invalid direct_server %q", v)
		}
		return nil
	}
	if strings.ContainsAny(v, "/ :") {
		return fmt.Errorf("invalid direct_server %q (want ip, ip:port or hostname)", v)
	}
	return nil
}

func clone(c apitypes.DNSConfig) apitypes.DNSConfig {
	out := apitypes.DNSConfig{
		Final: c.Final, Strategy: c.Strategy,
		DirectServer: c.DirectServer, DisableDirectSplit: c.DisableDirectSplit,
	}
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
