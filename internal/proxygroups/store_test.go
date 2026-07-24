package proxygroups

import (
	"os"
	"path/filepath"
	"reflect"
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

func TestStore_ExcludeCountries(t *testing.T) {
	s := newStore(t)
	// Fresh store seeds the default exclusion.
	if got := s.Get().ExcludeCountries; !reflect.DeepEqual(got, DefaultExcludeCountries) {
		t.Fatalf("fresh store exclude = %v, want %v", got, DefaultExcludeCountries)
	}
	// Explicit list is upper-cased, deduped, and invalid codes dropped.
	c, err := s.Set(Config{ExcludeCountries: []string{"hk", "HK", "us", "XYZ", "j"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.ExcludeCountries, []string{"HK", "US"}) {
		t.Fatalf("normalized exclude = %v, want [HK US]", c.ExcludeCountries)
	}
	// A nil field (caller omitted it) preserves the current value.
	c, _ = s.Set(Config{AutoCountry: true, ExcludeCountries: nil})
	if !reflect.DeepEqual(c.ExcludeCountries, []string{"HK", "US"}) {
		t.Fatalf("nil exclude should preserve, got %v", c.ExcludeCountries)
	}
	// An explicit empty slice means "exclude nothing".
	c, _ = s.Set(Config{ExcludeCountries: []string{}})
	if len(c.ExcludeCountries) != 0 {
		t.Fatalf("empty exclude should clear, got %v", c.ExcludeCountries)
	}
}

// A store file predating the field (no exclude_countries key) adopts the safe
// default once on load; an explicit empty list is left untouched.
func TestStore_ExcludeMigration(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(legacy, []byte(`{"auto_country":true,"groups":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Get().ExcludeCountries, DefaultExcludeCountries) {
		t.Fatalf("legacy store should migrate to default, got %v", s.Get().ExcludeCountries)
	}

	explicit := filepath.Join(dir, "explicit.json")
	if err := os.WriteFile(explicit, []byte(`{"auto_country":true,"exclude_countries":[],"groups":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s2, err := NewStore(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Get().ExcludeCountries) != 0 {
		t.Fatalf("explicit empty exclude must be kept, got %v", s2.Get().ExcludeCountries)
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
