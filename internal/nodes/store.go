// Package nodes is the "brain" side of multi-node management: a registry of
// remote trust-proxy gateways (probes). The brain reverse-proxies the browser's
// /api/nodes/{id}/* calls to each probe's /api with its bearer token, so tokens
// stay server-side and the browser talks to one origin.
package nodes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Node is a registered remote gateway.
//
// It has two independent uses, and the fields split along that line:
//
//   - **administering** it — URL + Token, reverse-proxied by the brain;
//   - **using it as an exit** — ProxyHost/ProxyPort plus this machine's account on
//     that gateway, injected as a socks outbound so it joins the proxy group next
//     to subscription nodes and WireGuard endpoints.
//
// The second is the point of multi-gateway: one cloud gateway holds the shared
// policy and the local machines just push their traffic through it, instead of
// every machine keeping its own copy of the rules.
//
// Token and ProxyPass are secrets and never leave the process (see Public).
type Node struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`

	// Exit use. ProxyHost defaults to the URL's host when empty.
	AsExit    bool   `json:"as_exit,omitempty"`
	ProxyHost string `json:"proxy_host,omitempty"`
	ProxyPort int    `json:"proxy_port,omitempty"`
	ProxyUser string `json:"proxy_user,omitempty"`
	ProxyPass string `json:"proxy_pass,omitempty"`

	// Disabled keeps a gateway registered but out of play — no exit outbound, and
	// the console leaves it alone. Stored inverted so an existing nodes.json (no
	// field) stays enabled.
	Disabled bool `json:"disabled,omitempty"`

	// Local marks the self-entry: this very gateway, listed so the console can show
	// one uniform list. Mode is "gateway" (runs a data plane) or "client" (console
	// only, exits through somebody else's gateway).
	Local bool   `json:"local,omitempty"`
	Mode  string `json:"mode,omitempty"`
}

// Public is a Node without its secrets (safe to return to the browser).
type Public struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	AsExit       bool   `json:"as_exit"`
	ProxyHost    string `json:"proxy_host,omitempty"`
	ProxyPort    int    `json:"proxy_port,omitempty"`
	ProxyUser    string `json:"proxy_user,omitempty"`
	HasProxyPass bool   `json:"has_proxy_pass"`
	Enabled      bool   `json:"enabled"`
	Local        bool   `json:"local,omitempty"`
	Mode         string `json:"mode,omitempty"`
}

// Modes a gateway entry can be in.
const (
	ModeGateway = "gateway" // runs a local data plane
	ModeClient  = "client"  // console only; traffic exits through a remote gateway
)

// ExitTag is the outbound tag for a gateway used as an exit. Prefixed so it
// cannot collide with a subscription node's tag.
func ExitTag(name string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '-'
	}, name)
	return "gw-" + safe
}

func idFor(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:])[:12]
}

// Store is a file-backed node registry.
type Store struct {
	path string
	mu   sync.Mutex
	data []Node
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = []Node{}
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
	return os.WriteFile(s.path, b, 0o600) // holds tokens
}

// List returns the public view (no tokens).
func (s *Store) List() []Public {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Public, 0, len(s.data))
	for _, n := range s.data {
		out = append(out, n.public())
	}
	return out
}

// Get returns the full node (with token) by id.
func (s *Store) Get(id string) (Node, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.data {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

// Add registers (or updates by URL) a node and persists.
func (s *Store) Add(name, url, token string) (Public, error) {
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if url == "" {
		return Public{}, fmt.Errorf("url is required")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	n := Node{ID: idFor(url), Name: strings.TrimSpace(name), URL: url, Token: token}
	if n.Name == "" {
		n.Name = url
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	replaced := false
	for i := range s.data {
		if s.data[i].ID == n.ID {
			s.data[i] = n
			replaced = true
			break
		}
	}
	if !replaced {
		s.data = append(s.data, n)
	}
	if err := s.save(); err != nil {
		return Public{}, err
	}
	return Public{ID: n.ID, Name: n.Name, URL: n.URL}, nil
}

// Delete removes a node by id.
// Patch applies a subset of the mutable fields to one entry.
//
// A nil field is left alone; an empty (non-nil) ProxyPass revokes the stored
// credential. Same reasoning as the user store: without pointers there is no way
// to say "leave this" and "clear this" apart, and merging them silently drops
// somebody's credential.
func (s *Store) Patch(id string, p PatchRequest) (Public, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data {
		n := &s.data[i]
		if n.ID != id {
			continue
		}
		if p.Name != nil {
			if *p.Name == "" {
				return Public{}, fmt.Errorf("name cannot be empty")
			}
			n.Name = *p.Name
		}
		if p.Enabled != nil {
			n.Disabled = !*p.Enabled
		}
		if p.AsExit != nil {
			n.AsExit = *p.AsExit
		}
		if p.ProxyHost != nil {
			n.ProxyHost = strings.TrimSpace(*p.ProxyHost)
		}
		if p.ProxyPort != nil {
			if *p.ProxyPort < 0 || *p.ProxyPort > 65535 {
				return Public{}, fmt.Errorf("proxy port must be 0-65535")
			}
			n.ProxyPort = *p.ProxyPort
		}
		if p.ProxyUser != nil {
			n.ProxyUser = strings.TrimSpace(*p.ProxyUser)
		}
		if p.ProxyPass != nil {
			n.ProxyPass = *p.ProxyPass
		}
		if p.Mode != nil {
			switch *p.Mode {
			case ModeGateway, ModeClient:
				n.Mode = *p.Mode
			default:
				return Public{}, fmt.Errorf("mode must be %s or %s", ModeGateway, ModeClient)
			}
		}
		if n.AsExit && !n.Local {
			// A gateway marked as an exit but with nowhere to dial is a switch that
			// silently does nothing, so say it now rather than at select time.
			host := n.ProxyHost
			if host == "" {
				host = hostOf(n.URL)
			}
			if host == "" || n.ProxyPort == 0 {
				return Public{}, fmt.Errorf("to use %q as an exit it needs a proxy host and port", n.Name)
			}
		}
		return n.public(), s.save()
	}
	return Public{}, fmt.Errorf("no such gateway")
}

// PatchRequest is the mutable part of a gateway entry.
type PatchRequest struct {
	Name      *string `json:"name,omitempty"`
	Enabled   *bool   `json:"enabled,omitempty"`
	AsExit    *bool   `json:"as_exit,omitempty"`
	ProxyHost *string `json:"proxy_host,omitempty"`
	ProxyPort *int    `json:"proxy_port,omitempty"`
	ProxyUser *string `json:"proxy_user,omitempty"`
	ProxyPass *string `json:"proxy_pass,omitempty"`
	Mode      *string `json:"mode,omitempty"`
}

// EnsureLocal makes sure the self-entry exists, so the console can show one
// uniform list of gateways instead of "this machine" living somewhere else.
func (s *Store) EnsureLocal(name string) Public {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data {
		if s.data[i].Local {
			return s.data[i].public()
		}
	}
	n := Node{ID: "local", Name: name, Local: true, Mode: ModeGateway}
	s.data = append(s.data, n)
	_ = s.save()
	return n.public()
}

// LocalMode reports whether this instance runs a data plane ("gateway") or is a
// console for somebody else's ("client").
func (s *Store) LocalMode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.data {
		if n.Local {
			if n.Mode == ModeClient {
				return ModeClient
			}
			return ModeGateway
		}
	}
	return ModeGateway
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.data[:0:0]
	found := false
	for _, n := range s.data {
		if n.ID == id {
			found = true
			continue
		}
		out = append(out, n)
	}
	if !found {
		return fmt.Errorf("node %q not found", id)
	}
	s.data = out
	return s.save()
}

// public strips the secrets.
func (n Node) public() Public {
	return Public{
		ID: n.ID, Name: n.Name, URL: n.URL,
		AsExit: n.AsExit, ProxyHost: n.ProxyHost, ProxyPort: n.ProxyPort,
		ProxyUser: n.ProxyUser, HasProxyPass: n.ProxyPass != "",
		Enabled: !n.Disabled, Local: n.Local, Mode: n.Mode,
	}
}

// ExitNodes returns the gateways this machine may egress through, already shaped
// as outbound nodes.
//
// A gateway used as an exit is, from the data plane's point of view, just another
// node: a socks outbound with credentials. Expressing it that way means the proxy
// group, the select, delay checks, Final targets and custom `node` rules all work
// on it with no new plumbing — and "switch my exit gateway" is the proxy-group
// select that already exists.
func (s *Store) ExitNodes() []apitypes.Node {
	out := []apitypes.Node{}
	for _, e := range s.Exits() {
		ob := map[string]any{
			"type": "socks", "version": "5", "tag": e.Tag,
			"server": e.Server, "server_port": e.Port,
		}
		if e.Username != "" {
			ob["username"], ob["password"] = e.Username, e.Password
		}
		raw, err := json.Marshal(ob)
		if err != nil {
			continue
		}
		out = append(out, apitypes.Node{
			Tag: e.Tag, Protocol: "socks", Server: e.Server, Port: e.Port, Outbound: raw,
		})
	}
	return out
}

// Exits returns the usable gateway exits.
func (s *Store) Exits() []Exit {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Exit
	for _, n := range s.data {
		if n.Disabled || n.Local || !n.AsExit {
			continue
		}
		host, port := n.ProxyHost, n.ProxyPort
		if host == "" {
			host = hostOf(n.URL)
		}
		if host == "" || port == 0 {
			continue // not usable as an exit yet; the console shows it as unconfigured
		}
		out = append(out, Exit{
			Tag: ExitTag(n.Name), Server: host, Port: port,
			Username: n.ProxyUser, Password: n.ProxyPass,
		})
	}
	return out
}

// Exit is one gateway expressed as an egress.
type Exit struct {
	Tag      string
	Server   string
	Port     int
	Username string
	Password string
}

// hostOf pulls the hostname out of a probe URL.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
