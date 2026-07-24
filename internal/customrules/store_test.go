package customrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "customrules.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAdd_ValidatesAndDerivesID(t *testing.T) {
	s := newStore(t)
	r, err := s.Add(apitypes.CustomRule{Match: "domain_suffix", Value: "Example.com", Action: "proxy", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rules) != 1 || r.Rules[0].ID == "" {
		t.Fatalf("want 1 rule with an ID, got %+v", r.Rules)
	}
	if r.Rules[0].Value != "example.com" {
		t.Fatalf("domain should be lowercased, got %q", r.Rules[0].Value)
	}

	// Idempotent: same match+value+action overwrites, not duplicates.
	r, _ = s.Add(apitypes.CustomRule{Match: "domain_suffix", Value: "example.com", Action: "proxy"})
	if len(r.Rules) != 1 {
		t.Fatalf("idempotent add should not duplicate, got %d", len(r.Rules))
	}
}

func TestAdd_Rejects(t *testing.T) {
	s := newStore(t)
	for _, tc := range []struct {
		name string
		r    apitypes.CustomRule
	}{
		{"bad regex", apitypes.CustomRule{Match: "regex", Value: "([", Action: "direct"}},
		{"bad ip", apitypes.CustomRule{Match: "ip_cidr", Value: "not-an-ip", Action: "direct"}},
		{"node without tag", apitypes.CustomRule{Match: "domain", Value: "x.com", Action: "node"}},
		{"unknown action", apitypes.CustomRule{Match: "domain", Value: "x.com", Action: "wat"}},
		{"unknown match", apitypes.CustomRule{Match: "port", Value: "80", Action: "direct"}},
		{"empty value", apitypes.CustomRule{Match: "domain", Value: "", Action: "direct"}},
	} {
		if _, err := s.Add(tc.r); err == nil {
			t.Fatalf("%s: expected rejection", tc.name)
		}
	}
	if len(s.Get().Rules) != 0 {
		t.Fatal("no invalid rule should have been stored")
	}
}

func TestMove_Reorders(t *testing.T) {
	s := newStore(t)
	a, _ := s.Add(apitypes.CustomRule{Match: "domain", Value: "a.com", Action: "direct"})
	_, _ = s.Add(apitypes.CustomRule{Match: "domain", Value: "b.com", Action: "direct"})
	idA := a.Rules[0].ID
	// a is at index 0; move it down.
	r, _ := s.Move(idA, 1)
	if r.Rules[1].Value != "a.com" {
		t.Fatalf("move down failed: %+v", r.Rules)
	}
	// move back up.
	r, _ = s.Move(idA, -1)
	if r.Rules[0].Value != "a.com" {
		t.Fatalf("move up failed: %+v", r.Rules)
	}
	// out-of-range move is a no-op.
	r, _ = s.Move(idA, -1)
	if r.Rules[0].Value != "a.com" {
		t.Fatalf("out-of-range move should be a no-op: %+v", r.Rules)
	}
}

func TestSanitize_DropsInvalidOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "customrules.json")
	// One valid + two invalid rules on disk.
	bad := `{"rules":[
      {"id":"x","match":"domain","value":"ok.com","action":"direct","enabled":true},
      {"id":"y","match":"regex","value":"([","action":"direct","enabled":true},
      {"id":"z","match":"ip_cidr","value":"nope","action":"proxy","enabled":true}
    ]}`
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rules := s.Get().Rules
	if len(rules) != 1 || rules[0].Value != "ok.com" {
		t.Fatalf("sanitize should keep only the valid rule, got %+v", rules)
	}
}

func TestPacks(t *testing.T) {
	s := newStore(t)
	// Applying a preset = Add each custom rule (tagged + enabled). Rule-set-only
	// packs (Google) are exercised via the API layer, not the CR store.
	apply := func(p apitypes.PackPreset) {
		for _, r := range p.Rules {
			if _, err := s.Add(r); err != nil {
				t.Fatalf("apply %s: %v", p.Name, err)
			}
		}
	}
	var dev, claude apitypes.PackPreset
	for _, p := range Presets {
		if p.Name == "Dev" {
			dev = p
		}
		if p.Name == "Claude" {
			claude = p
		}
	}
	if len(dev.Rules) == 0 || len(claude.Rules) == 0 {
		t.Fatal("Dev/Claude presets must still ship custom rules for this store test")
	}
	apply(dev)
	apply(claude)
	count := func(pack string) (total, enabled int) {
		for _, r := range s.Get().Rules {
			if r.Pack == pack {
				total++
				if r.Enabled {
					enabled++
				}
			}
		}
		return
	}
	if td, _ := count("Dev"); td != len(dev.Rules) {
		t.Fatalf("Dev pack has %d rules, want %d", td, len(dev.Rules))
	}
	// Idempotent re-apply doesn't duplicate.
	apply(dev)
	if td, _ := count("Dev"); td != len(dev.Rules) {
		t.Fatalf("re-apply duplicated Dev: %d", td)
	}

	// Disable the Dev pack only.
	if _, err := s.SetPackEnabled("Dev", false); err != nil {
		t.Fatal(err)
	}
	if _, de := count("Dev"); de != 0 {
		t.Fatalf("Dev should be all-disabled, %d still enabled", de)
	}
	if _, ce := count("Claude"); ce != len(claude.Rules) {
		t.Fatalf("Claude must be untouched, enabled=%d want %d", ce, len(claude.Rules))
	}

	// Remove the Dev pack only.
	if _, err := s.RemovePack("Dev"); err != nil {
		t.Fatal(err)
	}
	if td, _ := count("Dev"); td != 0 {
		t.Fatalf("Dev should be gone, %d remain", td)
	}
	if ct, _ := count("Claude"); ct != len(claude.Rules) {
		t.Fatalf("Claude must survive Dev removal, %d", ct)
	}
}

func TestSingboxMatchKey(t *testing.T) {
	for m, want := range map[string]string{
		"domain": "domain", "domain_suffix": "domain_suffix", "keyword": "domain_keyword",
		"regex": "domain_regex", "ip_cidr": "ip_cidr",
	} {
		if got, ok := SingboxMatchKey(m); !ok || got != want {
			t.Fatalf("SingboxMatchKey(%q)=%q,%v want %q", m, got, ok, want)
		}
	}
	if _, ok := SingboxMatchKey("bogus"); ok {
		t.Fatal("bogus match should not map")
	}
}
