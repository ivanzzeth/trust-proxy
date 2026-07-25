package apitypes

// Posture is the global Strict|Split operating posture (single-machine).
// Not Segments: one active posture at a time, dual-slot policy state.
const (
	PostureStrict = "strict" // default-deny ACL gate
	PostureSplit  = "split"  // human browse: gate open, Final egress, L1 floor stays
)

// ValidPosture reports whether p is a known posture name.
func ValidPosture(p string) bool {
	return p == PostureStrict || p == PostureSplit
}

// PolicySlot is one posture's full dual-slot policy surface (everything that
// switches with Strict↔Split except subscriptions/nodes and capture mode).
type PolicySlot struct {
	Whitelist   Rules              `json:"whitelist"`
	Blacklist   Blacklist          `json:"blacklist,omitempty"`
	Directlist  DirectList         `json:"directlist,omitempty"`
	CustomRules []CustomRule       `json:"custom_rules,omitempty"`
	RuleSets    []RuleSet          `json:"rule_sets,omitempty"`
	ProxyGroups *ProxyGroupsConfig `json:"proxy_groups,omitempty"`
	DNS         *DNSConfig         `json:"dns,omitempty"`
	Final       string             `json:"final,omitempty"`
	// Seeded is set on the Split slot after the first auto-import of all packs.
	Seeded bool `json:"seeded,omitempty"`
}
