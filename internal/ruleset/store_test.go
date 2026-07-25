package ruleset

import (
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestStore_SetReplacesAll(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir + "/rs.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Add(apitypes.RuleSet{Tag: "old", Name: "Old", Type: "remote", Format: "binary", URL: "u", Role: apitypes.RuleRoleBlock, Enabled: true})
	got, err := s.Set(Sets{Sets: []apitypes.RuleSet{
		{Tag: "new", Name: "New", Type: "remote", Format: "binary", URL: "u2", Role: apitypes.RuleRoleAllowProxy, Enabled: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sets) != 1 || got.Sets[0].Tag != "new" {
		t.Fatalf("Set should replace, got %+v", got)
	}
	again := s.Get()
	if len(again.Sets) != 1 || again.Sets[0].Tag != "new" {
		t.Fatalf("persisted Get: %+v", again)
	}
}

func TestAddRejectsInvalidRole(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir + "/rs.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(apitypes.RuleSet{Tag: "x", Type: "remote", URL: "u", Role: "bogus-role", Enabled: true}); err == nil {
		t.Fatal("expected invalid role to be rejected")
	}
	if len(s.Get().Sets) != 0 {
		t.Fatal("rejected add must not be persisted")
	}
}

func TestSetRoleRejectsInvalidRole(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir + "/rs.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(apitypes.RuleSet{Tag: "x", Type: "remote", URL: "u", Role: apitypes.RuleRolePermit, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRole("x", "bogus-role"); err == nil {
		t.Fatal("expected invalid role to be rejected")
	}
	if got := s.Get().Sets[0].Role; got != apitypes.RuleRolePermit {
		t.Fatalf("role must be unchanged after rejected SetRole, got %q", got)
	}
}

func TestNewStoreSanitizesUnknownRoleOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/rs.json"
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(apitypes.RuleSet{Tag: "x", Type: "remote", URL: "u", Role: apitypes.RuleRolePermit, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// Simulate corruption: hand-edit the persisted role to something invalid,
	// bypassing Add/SetRole's own validation.
	sets := s.Get()
	sets.Sets[0].Role = "corrupted-role"
	if _, err := s.Set(sets); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := reloaded.Get().Sets[0]
	if got.Enabled {
		t.Fatalf("expected a set with an unrecognized role to be disabled on load, got %+v", got)
	}
}
