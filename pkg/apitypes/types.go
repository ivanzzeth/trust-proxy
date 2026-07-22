// Package apitypes holds the wire types shared by the backend API
// (internal/api), the domain store (internal/subscription) and the SDK
// (pkg/client). It has no dependencies on those packages, avoiding import
// cycles.
package apitypes

import "encoding/json"

// Node is a single proxy node parsed out of a subscription. Outbound is the
// full sing-box outbound object (JSON) used when applying to the data plane;
// the other fields are for display.
type Node struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Server   string          `json:"server"`
	Port     int             `json:"port"`
	Outbound json.RawMessage `json:"outbound,omitempty"`
}

// Subscription is a remote proxy-provider URL and the nodes parsed from it.
type Subscription struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Content   string `json:"content,omitempty"` // manual/pasted node text (no fetch)
	UserAgent string `json:"user_agent,omitempty"`
	Via       string `json:"via,omitempty"` // fetch through this proxy (socks5:// or http://)
	Nodes     []Node `json:"nodes,omitempty"`
	NodeCount int    `json:"node_count"`
	UpdatedAt string `json:"updated_at,omitempty"`
	LastError string `json:"last_error,omitempty"`
	Applied   bool   `json:"applied,omitempty"`
}

// AddSubscriptionRequest is the POST /api/subscriptions body.
type AddSubscriptionRequest struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Content   string `json:"content,omitempty"` // paste node text directly (manual, no fetch)
	UserAgent string `json:"user_agent,omitempty"`
	Via       string `json:"via,omitempty"`
}

// RuleSet is an imported sing-box rule_set (remote .srs/.json or local file)
// plus the role it plays in our default-deny route (block / allow-direct /
// allow-proxy). Tag is the primary key referenced by route rules.
type RuleSet struct {
	Tag            string `json:"tag"`
	Name           string `json:"name"`
	Type           string `json:"type"`   // "remote" | "local"
	Format         string `json:"format"` // "binary" (.srs) | "source" (.json)
	URL            string `json:"url,omitempty"`
	Path           string `json:"path,omitempty"`
	DownloadDetour string `json:"download_detour"` // default "direct"
	UpdateInterval string `json:"update_interval"` // e.g. "1d"
	Role           string `json:"role"`            // "block" | "allow-direct" | "allow-proxy"
	Enabled        bool   `json:"enabled"`
}

// Rule-set roles.
const (
	RuleRoleBlock       = "block"
	RuleRoleAllowDirect = "allow-direct"
	RuleRoleAllowProxy  = "allow-proxy"
)

// RuleSetCatalogEntry is a one-click importable public rule set.
type RuleSetCatalogEntry struct {
	Tag           string `json:"tag"`
	Name          string `json:"name"`
	URL           string `json:"url"`             // raw.githubusercontent primary
	Mirror        string `json:"mirror"`          // jsdelivr CDN alternative
	Format        string `json:"format"`          // "binary" | "source"
	SuggestedRole string `json:"suggested_role"`  // default role on import
}

// AddRuleSetRequest is the POST /api/rulesets body. Either provide a full
// descriptor (tag/type/format/url|path) or a catalog_tag to import from the
// curated catalog.
type AddRuleSetRequest struct {
	CatalogTag string `json:"catalog_tag,omitempty"`
	Mirror     bool   `json:"mirror,omitempty"` // use the CDN mirror URL for a catalog import
	Tag        string `json:"tag,omitempty"`
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
	Format     string `json:"format,omitempty"`
	URL        string `json:"url,omitempty"`
	Path       string `json:"path,omitempty"`
	Role       string `json:"role,omitempty"`
}

// PatchRuleSetRequest is the PATCH /api/rulesets/{tag} body.
type PatchRuleSetRequest struct {
	Enabled *bool   `json:"enabled,omitempty"`
	Role    *string `json:"role,omitempty"`
}

// Profile bundles a named policy set (applied subscription + whitelist snapshot
// + enabled rule-set tags + optional capture mode) for one-click switching.
type Profile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	SubID       string   `json:"subscription_id,omitempty"`
	Whitelist   Rules    `json:"whitelist"`
	RuleSetTags []string `json:"ruleset_tags,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Active      bool     `json:"active,omitempty"`
}

// Rules is the egress allow-list snapshot (mirrors whitelist.Rules) embedded in
// a Profile; kept here so apitypes stays dependency-free.
type Rules struct {
	Domains   []string `json:"domains"`
	IPs       []string `json:"ips"`
	Processes []string `json:"processes"`
	Devices   []string `json:"devices"`
}

// DNSServer is one resolver. Type: local (system) | udp | tcp | tls | https |
// quic | fakeip | hosts. Non-local network servers take Server(+Port) and an
// optional Detour outbound ("direct" or "proxy") — Detour="proxy" resolves
// through the exit node so DNS isn't leaked to the local network. fakeip takes
// Inet4Range/Inet6Range (no address/detour); hosts takes a Records map
// (host -> [ips], no address/detour).
type DNSServer struct {
	Tag        string              `json:"tag"`
	Type       string              `json:"type"`
	Server     string              `json:"server,omitempty"`
	Port       int                 `json:"port,omitempty"`
	Detour     string              `json:"detour,omitempty"`
	Inet4Range string              `json:"inet4_range,omitempty"` // fakeip: default 198.18.0.0/15
	Inet6Range string              `json:"inet6_range,omitempty"` // fakeip: default fc00::/18
	Records    map[string][]string `json:"records,omitempty"`     // hosts: host -> [ips]
}

// DNSRule routes matching queries to a server tag (split-DNS).
type DNSRule struct {
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	RuleSet      []string `json:"rule_set,omitempty"`
	Server       string   `json:"server"`
}

// DNSConfig is the whole resolver policy (injected into sing-box's dns block).
type DNSConfig struct {
	Servers  []DNSServer `json:"servers"`
	Rules    []DNSRule   `json:"rules"`
	Final    string      `json:"final,omitempty"`
	Strategy string      `json:"strategy,omitempty"` // "" | prefer_ipv4 | prefer_ipv6 | ipv4_only | ipv6_only
}

// InboundAuth is the optional username/password required on the mixed proxy
// inbound (:17070). Both empty = auth disabled = the inbound is open.
type InboundAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TUNConfig tunes the tun inbound the gateway builds in TUN mode. Only takes
// effect when the capture mode is "tun"; otherwise the values are inert.
type TUNConfig struct {
	Stack          string   `json:"stack"`                     // system | gvisor | mixed (default gvisor)
	MTU            int      `json:"mtu"`                       // 0 = auto (omit "mtu")
	StrictRoute    bool     `json:"strict_route"`              // default true
	ExcludePackage []string `json:"exclude_package,omitempty"` // Android: packages routed AROUND the tun
	IncludePackage []string `json:"include_package,omitempty"` // Android: only these packages routed INTO the tun
	ExcludeProcess []string `json:"exclude_process,omitempty"` // process names routed AROUND the tun
}

// ErrorResponse is the standard error envelope.
type ErrorResponse struct {
	Error string `json:"error"`
}
