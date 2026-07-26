package nodes

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A gateway used as an exit is expressed as an ordinary outbound node. That is the
// whole trick: the proxy group, the select, delay checks and `node` rule targets
// then work on it with no special case anywhere.
func TestExitNodesAreOrdinarySocksOutbounds(t *testing.T) {
	s := newStore(t)
	gw, err := s.Add("cloud", "http://gw.example:21585", "tok")
	if err != nil {
		t.Fatal(err)
	}
	// Not an exit yet: nothing to egress through.
	if len(s.ExitNodes()) != 0 {
		t.Fatal("a registered gateway must not become an exit on its own")
	}
	// Marking it an exit without an address is refused, rather than producing a
	// switch that silently does nothing.
	yes := true
	if _, err := s.Patch(gw.ID, PatchRequest{AsExit: &yes}); err == nil {
		t.Fatal("as_exit with no proxy port should be refused")
	}
	port := 21584
	user, pass := "alice", "alice-proxy-pw"
	if _, err := s.Patch(gw.ID, PatchRequest{AsExit: &yes, ProxyPort: &port, ProxyUser: &user, ProxyPass: &pass}); err != nil {
		t.Fatal(err)
	}
	exits := s.ExitNodes()
	if len(exits) != 1 {
		t.Fatalf("got %d exits", len(exits))
	}
	e := exits[0]
	if e.Tag != "gw-cloud" || e.Server != "gw.example" || e.Port != 21584 {
		t.Fatalf("exit node = %+v", e)
	}
	var ob map[string]any
	if err := json.Unmarshal(e.Outbound, &ob); err != nil {
		t.Fatal(err)
	}
	if ob["type"] != "socks" || ob["username"] != "alice" || ob["password"] != "alice-proxy-pw" {
		t.Fatalf("outbound = %v", ob)
	}
	// The proxy host defaults to the admin URL's host, so the common case needs
	// one field, not two.
	if ob["server"] != "gw.example" {
		t.Fatalf("server = %v, want the URL's host", ob["server"])
	}

	// Disabling takes it out of play without forgetting the configuration.
	no := false
	if _, err := s.Patch(gw.ID, PatchRequest{Enabled: &no}); err != nil {
		t.Fatal(err)
	}
	if len(s.ExitNodes()) != 0 {
		t.Fatal("a disabled gateway must not be an exit")
	}
}

// The credential must never reach the browser, exactly like the admin token.
func TestPublicHidesSecrets(t *testing.T) {
	s := newStore(t)
	gw, _ := s.Add("cloud", "http://gw.example:21585", "admin-token")
	yes, port, pass := true, 21584, "alice-proxy-pw"
	user := "alice"
	if _, err := s.Patch(gw.ID, PatchRequest{AsExit: &yes, ProxyPort: &port, ProxyUser: &user, ProxyPass: &pass}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(s.List())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"admin-token", "alice-proxy-pw"} {
		if contains(string(raw), secret) {
			t.Errorf("the wire form leaks %q: %s", secret, raw)
		}
	}
	// …but it does say whether one is set, which the console needs.
	if !contains(string(raw), `"has_proxy_pass":true`) {
		t.Errorf("the console cannot tell a credential is configured: %s", raw)
	}
}

// The local entry exists so the console can show one list, and it says whether
// this instance runs a data plane at all.
func TestLocalEntryAndMode(t *testing.T) {
	s := newStore(t)
	local := s.EnsureLocal("laptop")
	if !local.Local || local.Mode != ModeGateway {
		t.Fatalf("local entry = %+v", local)
	}
	if again := s.EnsureLocal("laptop"); again.ID != local.ID {
		t.Fatal("EnsureLocal must not create a second self-entry")
	}
	if s.LocalMode() != ModeGateway {
		t.Fatalf("default mode = %q", s.LocalMode())
	}
	client := ModeClient
	if _, err := s.Patch("local", PatchRequest{Mode: &client}); err != nil {
		t.Fatal(err)
	}
	if s.LocalMode() != ModeClient {
		t.Fatalf("mode after patch = %q", s.LocalMode())
	}
	bogus := "whatever"
	if _, err := s.Patch("local", PatchRequest{Mode: &bogus}); err == nil {
		t.Fatal("an unknown mode must be refused")
	}
	// The local entry is never an exit: you do not egress through yourself.
	yes := true
	if _, err := s.Patch("local", PatchRequest{AsExit: &yes}); err != nil {
		t.Fatal(err)
	}
	if len(s.ExitNodes()) != 0 {
		t.Fatal("the local gateway must not appear as an exit")
	}
}

func contains(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
