package tuncfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestNewStore_SeedsAutoRedirect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tun.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if !got.AutoRedirect || !got.StrictRoute || got.Stack != "gvisor" {
		t.Fatalf("default = %+v, want auto_redirect+strict_route gvisor", got)
	}
}

// Upgrading a pre-auto_redirect store must turn the knobs on — otherwise a
// Linux box that already had tun.json would keep missing Docker egress after
// the binary upgrade, which is exactly the hole this field closes.
func TestNewStore_MigratesMissingAutoRedirect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tun.json")
	legacy := `{"stack":"gvisor","mtu":0,"strict_route":true}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Get().AutoRedirect {
		t.Fatal("missing auto_redirect key should migrate to true")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["auto_redirect"] != true {
		t.Fatalf("store rewrite missing auto_redirect=true: %s", raw)
	}
}

// An explicit false must survive reload — operators who turn it off (nft
// unavailable, deliberate) must not be flipped back on by migration.
func TestNewStore_PreservesExplicitFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tun.json")
	body := `{"stack":"gvisor","mtu":0,"strict_route":true,"auto_redirect":false}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Get().AutoRedirect {
		t.Fatal("explicit auto_redirect:false was overwritten")
	}
}

func TestSet_RejectsBadAddress(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "tun.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Set(apitypes.TUNConfig{Stack: "gvisor", Address: []string{"not-a-cidr"}})
	if err == nil {
		t.Fatal("expected invalid address error")
	}
}

func TestSet_AcceptsCustomAddress(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "tun.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Set(apitypes.TUNConfig{
		Stack:        "mixed",
		StrictRoute:  true,
		AutoRedirect: true,
		Address:      []string{"198.18.0.1/30"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Address) != 1 || got.Address[0] != "198.18.0.1/30" {
		t.Fatalf("address = %v", got.Address)
	}
}
