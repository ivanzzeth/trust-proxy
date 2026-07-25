package posture

import (
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// SeedSplit builds the first-time Split policy: every Allow pack preset
// (rules + catalog rule sets, roles merged on shared tags) plus geoip-cn
// route-direct, Final=proxy, and default Overseas-aware proxy groups.
func SeedSplit() apitypes.PolicySlot {
	slot := apitypes.PolicySlot{
		Final:  "proxy",
		Seeded: true,
		ProxyGroups: &apitypes.ProxyGroupsConfig{
			AutoCountry:      true,
			ExcludeCountries: append([]string(nil), proxygroups.DefaultExcludeCountries...),
		},
	}

	byTag := map[string]apitypes.RuleSet{}
	var rules []apitypes.CustomRule

	for _, preset := range customrules.Presets {
		for _, prs := range preset.RuleSets {
			entry, ok := ruleset.CatalogByTag(prs.CatalogTag)
			if !ok {
				continue
			}
			role := prs.Role
			if role == "" {
				role = entry.SuggestedRole
			}
			role = apitypes.NormalizeRuleRole(role)
			if existing, ok := byTag[entry.Tag]; ok {
				role = apitypes.MergeRuleRoles(existing.Role, role)
			}
			byTag[entry.Tag] = apitypes.RuleSet{
				Tag: entry.Tag, Name: entry.Name, Type: "remote", Format: entry.Format,
				URL: entry.URL, DownloadDetour: "direct", UpdateInterval: "1d",
				Role: role, Enabled: true,
			}
		}
		for _, r := range preset.Rules {
			rr := r
			rr.Pack = preset.Name
			rr.Enabled = true
			apitypes.NormalizeCustomRule(&rr)
			rules = append(rules, rr)
		}
	}

	// China IP ranges: packs only cover geosite-cn; IP-only CN needs geoip-cn.
	if entry, ok := ruleset.CatalogByTag("geoip-cn"); ok {
		role := apitypes.RuleRoleRouteDirect
		if existing, ok := byTag[entry.Tag]; ok {
			role = apitypes.MergeRuleRoles(existing.Role, role)
		}
		byTag[entry.Tag] = apitypes.RuleSet{
			Tag: entry.Tag, Name: entry.Name, Type: "remote", Format: entry.Format,
			URL: entry.URL, DownloadDetour: "direct", UpdateInterval: "1d",
			Role: role, Enabled: true,
		}
	}

	sets := make([]apitypes.RuleSet, 0, len(byTag))
	for _, rs := range byTag {
		sets = append(sets, rs)
	}
	slot.RuleSets = sets
	slot.CustomRules = rules
	return slot
}
