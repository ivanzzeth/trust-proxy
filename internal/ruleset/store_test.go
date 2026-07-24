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
