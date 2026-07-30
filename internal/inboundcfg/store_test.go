package inboundcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestZeroValueMeansBaseConfig(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "inbound.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Get(); got.Listen != "" || got.Port != 0 {
		t.Fatalf("fresh store should have no opinion, got %+v", got)
	}
	// Resolved is what the data plane would bind if it asked. The distinction
	// matters: Get()'s zero is what makes an untouched machine keep using its
	// own config.json.
	r := s.Resolved()
	if r.Listen != apitypes.DefaultInboundListen || r.Port != apitypes.DefaultInboundPort {
		t.Fatalf("Resolved = %+v, want the documented defaults", r)
	}
}

func TestSetPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(apitypes.InboundListen{Listen: "0.0.0.0", Port: 1080}); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Get(); got.Listen != "0.0.0.0" || got.Port != 1080 {
		t.Fatalf("reloaded %+v, want 0.0.0.0:1080", got)
	}
}

func TestValidateRejectsWhatWouldBrickTheGateway(t *testing.T) {
	cases := []struct {
		name string
		in   apitypes.InboundListen
		bad  bool
	}{
		{"zero is fine", apitypes.InboundListen{}, false},
		{"loopback", apitypes.InboundListen{Listen: "127.0.0.1", Port: 21584}, false},
		{"all interfaces", apitypes.InboundListen{Listen: "0.0.0.0", Port: 1080}, false},
		{"hostname is not an address", apitypes.InboundListen{Listen: "localhost"}, true},
		{"garbage address", apitypes.InboundListen{Listen: "1.2.3"}, true},
		{"port too high", apitypes.InboundListen{Port: 70000}, true},
		{"negative port", apitypes.InboundListen{Port: -1}, true},
		// These two are the ones that would produce a gateway whose console or
		// Clash API is silently shadowed by the proxy.
		{"console port", apitypes.InboundListen{Port: apiPort}, true},
		{"clash port", apitypes.InboundListen{Port: clashPort}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.in)
			if tc.bad && err == nil {
				t.Fatalf("Validate(%+v) accepted a value that would break the gateway", tc.in)
			}
			if !tc.bad && err != nil {
				t.Fatalf("Validate(%+v) = %v, want nil", tc.in, err)
			}
		})
	}
}

func TestSetRejectsWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(apitypes.InboundListen{Port: 1080}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(apitypes.InboundListen{Port: apiPort}); err == nil {
		t.Fatal("Set accepted the console port")
	}
	// A rejected write must not have moved the store, on disk or in memory —
	// a half-applied setting here is a gateway nobody can reach.
	if got := s.Get(); got.Port != 1080 {
		t.Fatalf("rejected Set changed the value to %+v", got)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var on apitypes.InboundListen
	if err := json.Unmarshal(b, &on); err != nil {
		t.Fatal(err)
	}
	if on.Port != 1080 {
		t.Fatalf("rejected Set reached the file: %+v", on)
	}
}

func TestDamagedFileSelfHealsInsteadOfBlockingStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("a damaged file must not stop the gateway from booting: %v", err)
	}
	if got := s.Get(); got != (apitypes.InboundListen{}) {
		t.Fatalf("want the zero value after self-heal, got %+v", got)
	}
}

func TestInvalidStoredValueSelfHeals(t *testing.T) {
	// Written by hand, or by an older/newer build with different rules: the file
	// parses but names our own console port. Booting with it would mean the
	// console vanishes on a machine whose only remaining access might be that
	// console.
	path := filepath.Join(t.TempDir(), "inbound.json")
	if err := os.WriteFile(path, []byte(`{"port":21585}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Get(); got.Port != 0 {
		t.Fatalf("invalid stored port survived load: %+v", got)
	}
}

func TestIsLoopback(t *testing.T) {
	cases := map[string]struct {
		in   apitypes.InboundListen
		want bool
	}{
		"default is loopback":    {apitypes.InboundListen{}, true},
		"explicit loopback":      {apitypes.InboundListen{Listen: "127.0.0.1"}, true},
		"ipv6 loopback":          {apitypes.InboundListen{Listen: "::1"}, true},
		"all interfaces is not":  {apitypes.InboundListen{Listen: "0.0.0.0"}, false},
		"a LAN address is not":   {apitypes.InboundListen{Listen: "192.168.1.10"}, false},
		"ipv6 wildcard is not":   {apitypes.InboundListen{Listen: "::"}, false},
		"port alone is loopback": {apitypes.InboundListen{Port: 1080}, true},
	}
	for name, tc := range cases {
		if got := IsLoopback(tc.in); got != tc.want {
			t.Errorf("%s: IsLoopback(%+v) = %v, want %v", name, tc.in, got, tc.want)
		}
	}
}
