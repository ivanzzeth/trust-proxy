// Package endpoints stores WireGuard / Tailscale exit endpoints (sing-box
// `endpoints[]`). Enabled ones are injected by the gateway and joined into the
// `proxy` group, so whitelisted egress can exit through a WireGuard tunnel or a
// Tailscale tailnet — alongside subscription proxy nodes.
package endpoints

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

// Store is a file-backed endpoint list (holds secrets; 0600).
type Store struct {
	path string
	mu   sync.Mutex
	data []apitypes.Endpoint
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = []apitypes.Endpoint{}
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
	return os.WriteFile(s.path, b, 0o600) // holds private/auth keys
}

// All returns the full endpoints (with secrets) for the gateway.
func (s *Store) All() []apitypes.Endpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]apitypes.Endpoint(nil), s.data...)
}

// List returns the public view (secrets stripped) for the browser.
func (s *Store) List() []apitypes.EndpointPublic {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]apitypes.EndpointPublic, 0, len(s.data))
	for _, e := range s.data {
		out = append(out, apitypes.EndpointPublic{
			Tag: e.Tag, Type: e.Type, Enabled: e.Enabled,
			Address: e.Address, MTU: e.MTU, PeerEndpoint: e.PeerEndpoint, AllowedIPs: e.AllowedIPs,
			Hostname: e.Hostname, ExitNode: e.ExitNode, AcceptRoutes: e.AcceptRoutes,
		})
	}
	return out
}

func validate(e apitypes.Endpoint) error {
	if e.Tag == "" {
		return fmt.Errorf("tag is required")
	}
	switch e.Type {
	case "wireguard":
		if len(e.Address) == 0 || e.PrivateKey == "" || e.PeerPublicKey == "" || e.PeerEndpoint == "" {
			return fmt.Errorf("wireguard needs address, private_key, peer_public_key, peer_endpoint")
		}
		if _, _, err := net.SplitHostPort(e.PeerEndpoint); err != nil {
			return fmt.Errorf("peer_endpoint must be host:port")
		}
	case "tailscale":
		if e.AuthKey == "" {
			return fmt.Errorf("tailscale needs an auth_key")
		}
	default:
		return fmt.Errorf("type must be wireguard or tailscale")
	}
	return nil
}

// Add inserts (or overwrites by tag) and persists.
func (s *Store) Add(e apitypes.Endpoint) (apitypes.EndpointPublic, error) {
	if err := validate(e); err != nil {
		return apitypes.EndpointPublic{}, err
	}
	if !e.Enabled {
		e.Enabled = true // adding = enable by default
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	replaced := false
	for i := range s.data {
		if s.data[i].Tag == e.Tag {
			s.data[i] = e
			replaced = true
			break
		}
	}
	if !replaced {
		s.data = append(s.data, e)
	}
	if err := s.save(); err != nil {
		return apitypes.EndpointPublic{}, err
	}
	return apitypes.EndpointPublic{Tag: e.Tag, Type: e.Type, Enabled: e.Enabled}, nil
}

// SetEnabled toggles an endpoint.
func (s *Store) SetEnabled(tag string, enabled bool) ([]apitypes.Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for i := range s.data {
		if s.data[i].Tag == tag {
			s.data[i].Enabled = enabled
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("endpoint %q not found", tag)
	}
	return append([]apitypes.Endpoint(nil), s.data...), s.save()
}

// Delete removes an endpoint by tag.
func (s *Store) Delete(tag string) ([]apitypes.Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.data[:0:0]
	found := false
	for _, e := range s.data {
		if e.Tag == tag {
			found = true
			continue
		}
		out = append(out, e)
	}
	if !found {
		return nil, fmt.Errorf("endpoint %q not found", tag)
	}
	s.data = out
	return append([]apitypes.Endpoint(nil), s.data...), s.save()
}

// Restore overwrites the whole list (used to roll back after a failed apply).
func (s *Store) Restore(list []apitypes.Endpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = append([]apitypes.Endpoint(nil), list...)
	return s.save()
}

// ParseWgQuick converts a wg-quick .conf ([Interface]/[Peer]) into a WireGuard
// endpoint. tag names it.
func ParseWgQuick(tag, conf string) (apitypes.Endpoint, error) {
	e := apitypes.Endpoint{Tag: tag, Type: "wireguard", Enabled: true}
	section := ""
	for _, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		csv := func(s string) []string {
			var out []string
			for _, p := range strings.Split(s, ",") {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}
			return out
		}
		switch section {
		case "interface":
			switch k {
			case "address":
				e.Address = csv(v)
			case "privatekey":
				e.PrivateKey = v
			case "mtu":
				e.MTU, _ = strconv.Atoi(v)
			}
		case "peer":
			switch k {
			case "publickey":
				e.PeerPublicKey = v
			case "presharedkey":
				e.PeerPreSharedKey = v
			case "endpoint":
				e.PeerEndpoint = v
			case "allowedips":
				e.AllowedIPs = csv(v)
			case "persistentkeepalive":
				e.PersistentKeepalive, _ = strconv.Atoi(v)
			}
		}
	}
	if len(e.AllowedIPs) == 0 {
		e.AllowedIPs = []string{"0.0.0.0/0", "::/0"} // full-tunnel exit by default
	}
	if err := validate(e); err != nil {
		return apitypes.Endpoint{}, err
	}
	return e, nil
}
