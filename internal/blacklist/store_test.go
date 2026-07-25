package blacklist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreAddRemoveAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.AddDomain("ads.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddKeyword("tracker"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRegex(`^evil-\d+\.com$`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddIP("203.0.113.0/24"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRegex("("); err == nil {
		t.Fatal("expected invalid regex to be rejected")
	}
	if _, err := s.AddIP("not-a-cidr"); err == nil {
		t.Fatal("expected invalid ip/cidr to be rejected")
	}

	got := s.Get()
	if len(got.Domains) != 1 || len(got.Keywords) != 1 || len(got.Regexes) != 1 || len(got.IPs) != 1 {
		t.Fatalf("unexpected state after adds: %+v", got)
	}

	if _, err := s.RemoveDomain("ads.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := s.Get(); len(got.Domains) != 0 {
		t.Fatalf("expected domain removed, got %+v", got)
	}

	// Reload from disk: persisted state must survive.
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got2 := s2.Get()
	if len(got2.Keywords) != 1 || got2.Keywords[0] != "tracker" {
		t.Fatalf("reloaded store missing persisted keyword: %+v", got2)
	}
}

func TestStoreSanitizesBadEntriesOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.json")
	bad := `{"domains":[],"keywords":[],"regexes":["("],"ips":["not-a-cidr","10.0.0.0/8"]}`
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if len(got.Regexes) != 0 {
		t.Fatalf("expected uncompilable regex dropped, got %+v", got.Regexes)
	}
	if len(got.IPs) != 1 || got.IPs[0] != "10.0.0.0/8" {
		t.Fatalf("expected only the valid CIDR to survive, got %+v", got.IPs)
	}
}
