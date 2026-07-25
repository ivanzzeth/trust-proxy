package apitypes

// Policy axes: Permit (may this destination leave?) is orthogonal to Route
// (which egress does allowed traffic use?). Route never opens the ACL gate;
// Permit never selects an outbound.

// Rule-set roles (new + legacy). Prefer permit / route-* / deny going forward.
const (
	RuleRoleDeny               = "deny"
	RuleRolePermit             = "permit"
	RuleRoleRouteDirect        = "route-direct"
	RuleRoleRouteProxy         = "route-proxy"
	RuleRolePermitRouteDirect  = "permit+route-direct" // migration of allow-direct
	RuleRolePermitRouteProxy   = "permit+route-proxy"  // migration of allow-proxy

	// Legacy aliases — still accepted on load / migration.
	RuleRoleBlock       = "block"
	RuleRoleAllowDirect = "allow-direct"
	RuleRoleAllowProxy  = "allow-proxy"
)

// Custom egress values (L4). "none" = permit-only (no route rule).
const (
	CustomEgressNone   = "none"
	CustomEgressDirect = "direct"
	CustomEgressProxy  = "proxy"
	CustomEgressBlock  = "block"
	CustomEgressNode   = "node"
)

// NormalizeRuleRole maps legacy roles onto the orthogonal vocabulary.
// allow-direct/proxy become permit+route-* so a one-shot migration keeps
// prior behavior until the user strips the permit half.
func NormalizeRuleRole(role string) string {
	switch role {
	case RuleRoleBlock:
		return RuleRoleDeny
	case RuleRoleAllowDirect:
		return RuleRolePermitRouteDirect
	case RuleRoleAllowProxy:
		return RuleRolePermitRouteProxy
	default:
		return role
	}
}

// RuleRoleGrantsPermit reports whether a rule-set role joins the L3 allow-set.
func RuleRoleGrantsPermit(role string) bool {
	switch NormalizeRuleRole(role) {
	case RuleRolePermit, RuleRolePermitRouteDirect, RuleRolePermitRouteProxy:
		return true
	}
	return false
}

// RuleRoleIsDeny reports whether the role is an L1 hard reject.
func RuleRoleIsDeny(role string) bool {
	switch NormalizeRuleRole(role) {
	case RuleRoleDeny:
		return true
	}
	return false
}

// RuleRoleRouteEgress returns "direct", "proxy", or "" (no L4 route from role).
func RuleRoleRouteEgress(role string) string {
	switch NormalizeRuleRole(role) {
	case RuleRoleRouteDirect, RuleRolePermitRouteDirect:
		return "direct"
	case RuleRoleRouteProxy, RuleRolePermitRouteProxy:
		return "proxy"
	}
	return ""
}

// ValidRuleRole reports whether role is a known (new or legacy) value.
func ValidRuleRole(role string) bool {
	switch role {
	case RuleRoleDeny, RuleRolePermit, RuleRoleRouteDirect, RuleRoleRouteProxy,
		RuleRolePermitRouteDirect, RuleRolePermitRouteProxy,
		RuleRoleBlock, RuleRoleAllowDirect, RuleRoleAllowProxy:
		return true
	}
	return false
}

// ComposeRuleRole builds a role from the two axes.
func ComposeRuleRole(permit bool, route string) string {
	switch {
	case permit && route == "direct":
		return RuleRolePermitRouteDirect
	case permit && route == "proxy":
		return RuleRolePermitRouteProxy
	case permit:
		return RuleRolePermit
	case route == "direct":
		return RuleRoleRouteDirect
	case route == "proxy":
		return RuleRoleRouteProxy
	default:
		return ""
	}
}

// MergeRuleRoles unions Permit and Route axes (incoming route wins if both set).
func MergeRuleRoles(existing, incoming string) string {
	permit := RuleRoleGrantsPermit(existing) || RuleRoleGrantsPermit(incoming)
	route := RuleRoleRouteEgress(incoming)
	if route == "" {
		route = RuleRoleRouteEgress(existing)
	}
	return ComposeRuleRole(permit, route)
}

// SubtractRuleRoles removes the axes contributed by `remove` from `current`.
// Empty result means the rule-set can be deleted / disabled.
func SubtractRuleRoles(current, remove string) string {
	permit := RuleRoleGrantsPermit(current)
	if RuleRoleGrantsPermit(remove) {
		permit = false
	}
	route := RuleRoleRouteEgress(current)
	if RuleRoleRouteEgress(remove) != "" {
		route = ""
	}
	return ComposeRuleRole(permit, route)
}

// BoolPtr is a small helper for CustomRule.Permit literals in presets/tests.
func BoolPtr(v bool) *bool { return &v }

// GrantsPermit reports whether this custom rule joins the L3 allow-set.
// Explicit Permit wins; otherwise legacy Action≠block implies permit.
func (r CustomRule) GrantsPermit() bool {
	if r.Permit != nil {
		return *r.Permit
	}
	eg := r.effectiveEgress()
	return eg != "" && eg != CustomEgressBlock && eg != CustomEgressNone
}

// RouteEgress returns the L4 action (direct/proxy/block/node) or "" if this
// rule is permit-only (egress none / unset with no legacy action).
func (r CustomRule) RouteEgress() string {
	eg := r.effectiveEgress()
	if eg == CustomEgressNone {
		return ""
	}
	return eg
}

func (r CustomRule) effectiveEgress() string {
	if r.Egress != "" {
		return r.Egress
	}
	return r.Action
}

// NormalizeCustomRule fills Egress/Permit/Action from whichever fields are set
// so old JSON (action only) and new JSON (permit+egress) both work.
func NormalizeCustomRule(r *CustomRule) {
	if r == nil {
		return
	}
	if r.Egress == "" && r.Action != "" {
		r.Egress = r.Action
	}
	if r.Action == "" && r.Egress != "" && r.Egress != CustomEgressNone {
		r.Action = r.Egress
	}
	if r.Permit == nil {
		eg := r.effectiveEgress()
		var p bool
		switch eg {
		case CustomEgressBlock:
			p = false
		case CustomEgressNone:
			p = true // permit-only
		case "":
			p = false
		default:
			p = true // legacy direct/proxy/node
		}
		r.Permit = &p
	}
}
