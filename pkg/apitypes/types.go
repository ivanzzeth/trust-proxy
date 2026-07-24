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
	URL           string `json:"url"`            // raw.githubusercontent primary
	Mirror        string `json:"mirror"`         // jsdelivr CDN alternative
	Format        string `json:"format"`         // "binary" | "source"
	SuggestedRole string `json:"suggested_role"` // default role on import
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

// CustomRule is one ordered custom routing rule (the L4/routing layer): a
// matcher plus the egress it selects. Order is priority (first-match). Actions
// direct/proxy/node also imply "allow" (the matcher joins the ACL allow-set);
// block does not. A node action targets a single subscription/endpoint outbound
// by its (unstable) tag — the gateway skips the rule if that tag isn't a live
// outbound (self-heal), so a removed node can't brick the box.
type CustomRule struct {
	ID      string `json:"id"`    // sha256(match|value|action|node)[:12], idempotent
	Match   string `json:"match"` // domain | domain_suffix | keyword | regex | ip_cidr
	Value   string `json:"value"`
	Action  string `json:"action"`         // direct | proxy | block | node
	Node    string `json:"node,omitempty"` // target outbound tag (required when action==node)
	Pack    string `json:"pack,omitempty"` // optional named group (Allow pack); metadata only
	Enabled bool   `json:"enabled"`
}

// PackPreset is a curated, one-click-importable group of custom rules (an Allow
// pack): applying it Adds each rule tagged with Pack=Name, Enabled=true.
type PackPreset struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Exit        string       `json:"exit,omitempty"` // how the pack egresses: PackExit* (display hint)
	Rules       []CustomRule `json:"rules"`
}

// PackExit* describe how a preset's traffic leaves — a display hint for the UI.
const (
	PackExitOverseas = "overseas" // via the shared Overseas group (geofenced services)
	PackExitAuto     = "auto"     // via the default proxy group (fastest)
	PackExitDirect   = "direct"   // direct, no proxy
)

// Custom-rule actions + match kinds.
const (
	CustomActionDirect = "direct"
	CustomActionProxy  = "proxy"
	CustomActionBlock  = "block"
	CustomActionNode   = "node"

	CustomMatchDomain       = "domain"
	CustomMatchDomainSuffix = "domain_suffix"
	CustomMatchKeyword      = "keyword"
	CustomMatchRegex        = "regex"
	CustomMatchIPCIDR       = "ip_cidr"
)

// PatchCustomRuleRequest is the PATCH /api/customrules/{id} body (all optional).
type PatchCustomRuleRequest struct {
	Enabled *bool   `json:"enabled,omitempty"`
	Match   *string `json:"match,omitempty"`
	Value   *string `json:"value,omitempty"`
	Action  *string `json:"action,omitempty"`
	Node    *string `json:"node,omitempty"`
	Pack    *string `json:"pack,omitempty"`
}

// RuleView is one entry in the effective-policy explain view: a human-readable
// projection of a single generated route rule, labeled by the layer and store
// that produced it. It mirrors the order the gateway injects rules (first-match,
// top to bottom) so the UI can show "why is this allowed / blocked".
type RuleView struct {
	Layer   string   `json:"layer"`             // L0 | L1 | L2 | L3 | L4 | catch-all
	Source  string   `json:"source"`            // management | blacklist | rule-set:<tag> | process | device | global | no-proxy | private | custom | acl-gate | default-deny
	Action  string   `json:"action"`            // reject | route:blocked | route:direct | route:proxy | route:<node>
	Matcher string   `json:"matcher,omitempty"` // domain_suffix | ip_cidr | rule_set | process_name | source_ip_cidr | clash_mode | network | logical
	Values  []string `json:"values,omitempty"`  // truncated sample of the matcher's values
	Note    string   `json:"note,omitempty"`    // e.g. a custom node target that is currently missing
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

// Blacklist is the egress deny-list snapshot: destinations that are REJECTED
// even if an allow rule (whitelist / allow rule-set) would otherwise permit
// them. Domains match domain_suffix, Keywords match domain_keyword, Regexes
// match domain_regex, IPs match ip_cidr. Injected as reject rules above the
// allows so a blacklisted target is dropped first.
type Blacklist struct {
	Domains  []string `json:"domains"`
	Keywords []string `json:"keywords"`
	Regexes  []string `json:"regexes"`
	IPs      []string `json:"ips"`
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

// Endpoint is a WireGuard or Tailscale exit (sing-box `endpoints[]`). Enabled
// endpoints join the `proxy` group so whitelisted traffic can egress through
// them. Secret fields (private_key/pre_shared_key/auth_key) are never returned
// to the browser (see EndpointPublic).
type Endpoint struct {
	Tag     string `json:"tag"`
	Type    string `json:"type"` // "wireguard" | "tailscale"
	Enabled bool   `json:"enabled"`

	// wireguard
	Address             []string `json:"address,omitempty"` // local CIDRs
	PrivateKey          string   `json:"private_key,omitempty"`
	MTU                 int      `json:"mtu,omitempty"`
	PeerPublicKey       string   `json:"peer_public_key,omitempty"`
	PeerPreSharedKey    string   `json:"peer_pre_shared_key,omitempty"`
	PeerEndpoint        string   `json:"peer_endpoint,omitempty"` // host:port
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`

	// tailscale
	AuthKey      string `json:"auth_key,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	ExitNode     string `json:"exit_node,omitempty"`
	AcceptRoutes bool   `json:"accept_routes,omitempty"`
}

// EndpointPublic is an Endpoint with secrets stripped (browser-safe list view).
type EndpointPublic struct {
	Tag          string   `json:"tag"`
	Type         string   `json:"type"`
	Enabled      bool     `json:"enabled"`
	Address      []string `json:"address,omitempty"`
	MTU          int      `json:"mtu,omitempty"`
	PeerEndpoint string   `json:"peer_endpoint,omitempty"`
	AllowedIPs   []string `json:"allowed_ips,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	ExitNode     string   `json:"exit_node,omitempty"`
	AcceptRoutes bool     `json:"accept_routes,omitempty"`
}

// ErrorResponse is the standard error envelope.
type ErrorResponse struct {
	Error string `json:"error"`
}
