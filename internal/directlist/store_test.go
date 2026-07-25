package directlist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreAddRemoveAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directlist.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.AddDomain("intra.corp.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddIP("10.1.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddDomain("*"); err == nil {
		t.Fatal("expected overly-broad domain pattern to be rejected")
	}
	if _, err := s.AddIP("not-a-cidr"); err == nil {
		t.Fatal("expected invalid ip/cidr to be rejected")
	}

	got := s.Get()
	if len(got.Domains) != 1 || len(got.IPs) != 1 {
		t.Fatalf("unexpected state after adds: %+v", got)
	}

	if _, err := s.RemoveIP("10.1.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if got := s.Get(); len(got.IPs) != 0 {
		t.Fatalf("expected ip removed, got %+v", got)
	}

	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got2 := s2.Get(); len(got2.Domains) != 1 || got2.Domains[0] != "intra.corp.example" {
		t.Fatalf("reloaded store missing persisted domain: %+v", got2)
	}
}

func TestStoreSanitizesBadIPsOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directlist.json")
	bad := `{"domains":["ok.example"],"ips":["not-a-cidr","192.168.0.0/16"]}`
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if len(got.IPs) != 1 || got.IPs[0] != "192.168.0.0/16" {
		t.Fatalf("expected only the valid CIDR to survive, got %+v", got.IPs)
	}
}
