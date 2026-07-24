package api

import (
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestResolveProfileRuleSets_PrefersFullDescriptors(t *testing.T) {
	s := &Server{}
	p := apitypes.Profile{
		RuleSets: []apitypes.RuleSet{{
			Tag: "geosite-github", Name: "GitHub", Type: "remote", Format: "binary",
			URL: "https://example.com/g.srs", Role: apitypes.RuleRoleAllowProxy, Enabled: true,
		}},
		RuleSetTags: []string{"should-be-ignored"},
	}
	got := s.resolveProfileRuleSets(p)
	if len(got.Sets) != 1 || got.Sets[0].Tag != "geosite-github" {
		t.Fatalf("got %+v", got)
	}
	if got.Sets[0].DownloadDetour != "direct" || got.Sets[0].UpdateInterval != "1d" {
		t.Fatalf("defaults not filled: %+v", got.Sets[0])
	}
}

func TestResolveProfileRuleSets_LegacyTagsToggleEnabled(t *testing.T) {
	dir := t.TempDir()
	rs, err := ruleset.NewStore(dir + "/rulesets.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = rs.Add(apitypes.RuleSet{Tag: "a", Name: "A", Type: "remote", Format: "binary", URL: "u", Role: apitypes.RuleRoleAllowProxy, Enabled: true})
	_, _ = rs.Add(apitypes.RuleSet{Tag: "b", Name: "B", Type: "remote", Format: "binary", URL: "u", Role: apitypes.RuleRoleAllowProxy, Enabled: true})

	s := &Server{rs: rs}
	p := apitypes.Profile{RuleSetTags: []string{"b"}}
	got := s.resolveProfileRuleSets(p)
	var aOn, bOn bool
	for _, x := range got.Sets {
		if x.Tag == "a" {
			aOn = x.Enabled
		}
		if x.Tag == "b" {
			bOn = x.Enabled
		}
	}
	if aOn || !bOn {
		t.Fatalf("legacy tags: a=%v b=%v want a=false b=true", aOn, bOn)
	}
}

func TestResolveProfileRuleSets_FillsCatalogURL(t *testing.T) {
	s := &Server{}
	p := apitypes.Profile{
		RuleSets: []apitypes.RuleSet{{
			Tag: "geosite-github", Type: "remote", Enabled: true,
		}},
	}
	got := s.resolveProfileRuleSets(p)
	if len(got.Sets) != 1 || got.Sets[0].URL == "" {
		t.Fatalf("expected catalog URL fill, got %+v", got.Sets)
	}
}
