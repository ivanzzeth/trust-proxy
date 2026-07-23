package proxygroups

import (
	"path/filepath"
	"testing"
)

func TestCountry(t *testing.T) {
	cases := map[string]string{
		"🇭🇰 香港 01":        "HK",
		"Hong Kong IEPL":  "HK",
		"HK-Premium":      "HK",
		"🇺🇸 US West":      "US",
		"United States 1": "US",
		"日本 IPLC":         "JP",
		"🇯🇵 Tokyo":        "JP",
		"新加坡 SG":          "SG",
		"my random relay": "MY", // "my" keyword — acceptable heuristic
		"Frankfurt DE":    "DE",
		"unlabeled-node":  "",
	}
	for tag, want := range cases {
		if got := Country(tag); got != want {
			t.Errorf("Country(%q)=%q want %q", tag, got, want)
		}
	}
}

func TestCountryName(t *testing.T) {
	if got := CountryName("HK"); got != "🇭🇰 HK" {
		t.Errorf("CountryName(HK)=%q", got)
	}
	if got := CountryName("Auto"); got != "Auto" {
		t.Errorf("non-2-letter should pass through, got %q", got)
	}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "proxygroups.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStore_SeedAndSet(t *testing.T) {
	s := newStore(t)
	if !s.Get().AutoCountry {
		t.Fatal("fresh store should default AutoCountry=true")
	}
	// Valid config.
	c, err := s.Set(Config{AutoCountry: false, Groups: []Group{
		{Name: "Streaming", Type: "urltest", Filter: "regex", Value: "(?i)stream"},
		{Name: "Pinned", Type: "select", Filter: "manual", Nodes: []string{"HK-01"}},
	}})
	if err != nil || c.AutoCountry || len(c.Groups) != 2 {
		t.Fatalf("set valid failed: %+v err=%v", c, err)
	}
}

func TestStore_Rejects(t *testing.T) {
	s := newStore(t)
	for _, tc := range []struct {
		name string
		g    Group
	}{
		{"bad type", Group{Name: "A", Type: "loadbalance", Filter: "regex", Value: "x"}},
		{"bad filter", Group{Name: "B", Type: "urltest", Filter: "geoip", Value: "x"}},
		{"bad regex", Group{Name: "C", Type: "urltest", Filter: "regex", Value: "("}},
		{"reserved name", Group{Name: "proxy", Type: "urltest", Filter: "regex", Value: "x"}},
		{"empty name", Group{Name: "", Type: "urltest", Filter: "regex", Value: "x"}},
		{"manual no nodes", Group{Name: "D", Type: "select", Filter: "manual"}},
	} {
		if _, err := s.Set(Config{AutoCountry: true, Groups: []Group{tc.g}}); err == nil {
			t.Errorf("%s: expected rejection", tc.name)
		}
	}
	// Duplicate names rejected.
	if _, err := s.Set(Config{Groups: []Group{
		{Name: "X", Type: "urltest", Filter: "regex", Value: "a"},
		{Name: "x", Type: "urltest", Filter: "regex", Value: "b"},
	}}); err == nil {
		t.Error("duplicate group names should be rejected")
	}
}
