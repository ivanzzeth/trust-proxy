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
// plus the role it plays on the Permit / Route / Deny axes. Tag is the primary
// key referenced by route rules. See policy.go for role constants and helpers.
type RuleSet struct {
	Tag            string `json:"tag"`
	Name           string `json:"name"`
	Type           string `json:"type"`   // "remote" | "local"
	Format         string `json:"format"` // "binary" (.srs) | "source" (.json)
	URL            string `json:"url,omitempty"`
	Path           string `json:"path,omitempty"`
	DownloadDetour string `json:"download_detour"` // default "direct"
	UpdateInterval string `json:"update_interval"` // e.g. "1d"
	Role           string `json:"role"`            // deny|permit|route-direct|route-proxy|permit+route-*|legacy
	Enabled        bool   `json:"enabled"`
}

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

// CustomRule is one ordered policy rule on the Permit and/or Route axes.
// Order is priority for L4 (first-match). Permit and Egress are orthogonal:
//   - Permit=true joins the L3 allow-set (may leave the network)
//   - Egress selects L4 outbound (none = no route rule; Final applies)
//
// Legacy Action-only JSON is normalized via NormalizeCustomRule (action≠block
// ⇒ permit+egress). A node egress targets a subscription/endpoint/group tag;
// missing tags are skipped (self-heal).
type CustomRule struct {
	ID      string `json:"id"`    // sha256(match|value|action|node)[:12], idempotent
	Match   string `json:"match"` // domain | domain_suffix | keyword | regex | ip_cidr
	Value   string `json:"value"`
	Action  string `json:"action"`           // legacy/wire: direct|proxy|block|node (mirrors Egress)
	Egress  string `json:"egress,omitempty"` // none|direct|proxy|block|node
	Permit  *bool  `json:"permit,omitempty"` // nil ⇒ derive from Action/Egress (compat)
	Node    string `json:"node,omitempty"`   // target outbound tag (required when egress==node)
	Pack    string `json:"pack,omitempty"`   // optional named pack; metadata only
	Enabled bool   `json:"enabled"`
}

// PackPreset is a curated, one-click-importable policy pack. Applying it:
//   - imports each RuleSets entry with an explicit Role (permit and/or route);
//   - Adds each Rules entry tagged Pack=Name with explicit Permit/Egress.
//
// Either RuleSets or Rules (or both) may be non-empty.
type PackPreset struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Warning     string        `json:"warning,omitempty"` // shown before apply (e.g. China wide)
	Exit        string        `json:"exit,omitempty"`    // PackExit* display hint
	RuleSets    []PackRuleSet `json:"rule_sets,omitempty"`
	Rules       []CustomRule  `json:"rules"` // always a JSON array; may be empty when RuleSets-only
}

// PackRuleSet binds a pack to a public rule-set catalog tag. Role should be set
// explicitly (permit / route-* / deny); empty falls back to catalog SuggestedRole.
type PackRuleSet struct {
	CatalogTag string `json:"catalog_tag"`
	Role       string `json:"role,omitempty"`
}

// PackExit* describe how a preset's traffic leaves — a display hint for the UI.
const (
	PackExitOverseas = "overseas" // via the shared Overseas group (geofenced services)
	PackExitAuto     = "auto"     // via the default proxy group (fastest)
	PackExitDirect   = "direct"   // direct, no proxy
)

// Custom-rule actions (legacy aliases of CustomEgress*) + match kinds.
const (
	CustomActionDirect = CustomEgressDirect
	CustomActionProxy  = CustomEgressProxy
	CustomActionBlock  = CustomEgressBlock
	CustomActionNode   = CustomEgressNode
	CustomActionNone   = CustomEgressNone

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
	Egress  *string `json:"egress,omitempty"`
	Permit  *bool   `json:"permit,omitempty"`
	Node    *string `json:"node,omitempty"`
	Pack    *string `json:"pack,omitempty"`
}

// PackApplyResult is what applying a policy pack changed: the pack's rules plus
// the rule sets it imported (their roles merge into any shared tag).
type PackApplyResult struct {
	Rules []CustomRule `json:"rules"`
	// RuleSets are the pack's catalog bindings (catalog_tag + role), not full
	// rule-set descriptors — the descriptors live in the rule-set store.
	RuleSets []PackRuleSet `json:"rule_sets"`
}

// QuarantineEntry is one destination the gateway blocked by itself, with why and
// when. Released explicitly by an operator; never rewritten by a posture switch.
type QuarantineEntry struct {
	Value  string `json:"value"`
	IsIP   bool   `json:"is_ip"`
	Reason string `json:"reason"`
	Time   string `json:"time"`
}

// DetectionConfig is the tunable half of the detection engine. Every threshold
// that used to be a constant lives here so an operator can trade sensitivity for
// noise without a rebuild. Zero values mean "use the default" (see
// internal/detectcfg.Defaults), which is also what an older config file gets.
type DetectionConfig struct {
	// Beaconing: periodic re-connections to one destination.
	BeaconEnabled     bool    `json:"beacon_enabled"`
	BeaconMinSample   int     `json:"beacon_min_sample,omitempty"`     // connections before a cadence is judged
	BeaconCV          float64 `json:"beacon_cv,omitempty"`             // max interval coefficient of variation
	BeaconMinInterval int     `json:"beacon_min_interval_s,omitempty"` // ignore bursts faster than this
	BeaconMaxInterval int     `json:"beacon_max_interval_s,omitempty"` // ignore cadences slower than this
	BeaconReAlert     int     `json:"beacon_realert_s,omitempty"`      // floor for the re-alert cooldown
	// BeaconReAlertFactor multiplies the observed interval to get the cooldown:
	// a cadence is reported at most once per this many of its own periods. A
	// cooldown shorter than the cadence re-reports every cycle (~144 alerts/day
	// for one 10-minute poller), which is what buried the real findings.
	BeaconReAlertFactor int `json:"beacon_realert_factor,omitempty"`

	// DGA / DNS-tunnel scoring.
	DGAEnabled        bool    `json:"dga_enabled"`
	DGAMinLabelLen    int     `json:"dga_min_label_len,omitempty"`
	DGAMinEntropy     float64 `json:"dga_min_entropy,omitempty"`
	TunnelMinLabelLen int     `json:"tunnel_min_label_len,omitempty"`
	TunnelMinEntropy  float64 `json:"tunnel_min_entropy,omitempty"`
	SubdomainAlertAt  int     `json:"subdomain_alert_at,omitempty"` // distinct subdomains under one parent

	// Exfil: a large upload is only interesting when it is also *shaped* like
	// exfil — lopsided, or to a destination this gateway has never seen. Set
	// either signal to 0 to ignore it; with both off, any upload over the byte
	// threshold alerts (the old behaviour).
	ExfilUploadBytes  int64   `json:"exfil_upload_bytes,omitempty"`
	ExfilMinRatio     float64 `json:"exfil_min_ratio,omitempty"`      // upload/download ratio
	ExfilNewDestHours int     `json:"exfil_new_dest_hours,omitempty"` // "never seen in this window" counts as new

	// Disposal (auto-block / auto-ban).
	AutoBlock bool `json:"auto_block"`
	// RequireWarmPermit keeps disposal from running until the Permit index has
	// completed a warm pass. The index is built asynchronously and fetches remote
	// rule sets, so until it lands every rule-set-derived Permit reads as "not
	// permitted" — and a large upload in that window would ban a destination the
	// operator had in fact approved. Alerts are unaffected: fail open on
	// reporting, fail safe on disposal.
	RequireWarmPermit bool `json:"require_warm_permit"`
}

// ACLList is the wire shape shared by the three ACL stores. Each store fills
// only its own dimensions: Permit uses domains/ips/processes/devices, Deny adds
// keywords/regexes, No-Proxy uses domains/ips.
type ACLList struct {
	// Builtin are always-on entries the gateway owns (No-Proxy's LAN/private
	// ranges). Read-only: the API reports them so a client doesn't present the
	// list as if those ranges could be removed.
	Builtin   []string `json:"builtin,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	Processes []string `json:"processes,omitempty"`
	Devices   []string `json:"devices,omitempty"`
	Keywords  []string `json:"keywords,omitempty"`
	Regexes   []string `json:"regexes,omitempty"`
}

// FinalConfig is the catch-all egress for permitted-but-unrouted traffic.
type FinalConfig struct {
	Outbound string `json:"outbound"`
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

// Profile bundles a named full-policy snapshot for one-click switching: applied
// subscription, Permit/Deny/Route lists, rule sets, custom rules (packs),
// proxy-group config, DNS, and capture mode. Environment knobs (TUN/inbound
// auth/VPN endpoints) are intentionally excluded so activating a profile can't
// brick a remote probe's capture path.
type Profile struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Version     int                `json:"version,omitempty"` // policy schema; 2 = Permit⊥Route
	SubID       string             `json:"subscription_id,omitempty"`
	Whitelist   Rules              `json:"whitelist"`
	Blacklist   Blacklist          `json:"blacklist,omitempty"`
	Directlist  DirectList         `json:"directlist,omitempty"`
	CustomRules []CustomRule       `json:"custom_rules,omitempty"`
	RuleSets    []RuleSet          `json:"rule_sets,omitempty"`    // full descriptors (preferred)
	RuleSetTags []string           `json:"ruleset_tags,omitempty"` // legacy: enable-only tags
	ProxyGroups *ProxyGroupsConfig `json:"proxy_groups,omitempty"`
	DNS         *DNSConfig         `json:"dns,omitempty"`
	Final       string             `json:"final,omitempty"` // catch-all egress: proxy|direct|blocked|<tag>
	Mode        string             `json:"mode,omitempty"`
	Active      bool               `json:"active,omitempty"`
}

// ProfilePolicyVersion is written on new/updated profiles after the Permit⊥Route
// migration. Older snapshots are expanded on activate.
const ProfilePolicyVersion = 2

// Rules is the egress allow-list snapshot (mirrors whitelist.Rules) embedded in
// a Profile; kept here so apitypes stays dependency-free.
type Rules struct {
	Domains   []string `json:"domains"`
	IPs       []string `json:"ips"`
	Processes []string `json:"processes"`
	Devices   []string `json:"devices"`
}

// DirectList is the no-proxy / bypass snapshot (mirrors directlist.Rules).
type DirectList struct {
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
}

// ProxyGroup is one user-defined group in a Profile / proxygroups config.
type ProxyGroup struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`   // select | urltest
	Filter string   `json:"filter"` // country | regex | manual
	Value  string   `json:"value,omitempty"`
	Nodes  []string `json:"nodes,omitempty"`
}

// ProxyGroupsConfig mirrors internal/proxygroups.Config for wire/profile use.
type ProxyGroupsConfig struct {
	AutoCountry      bool         `json:"auto_country"`
	ExcludeCountries []string     `json:"exclude_countries"`
	Groups           []ProxyGroup `json:"groups"`
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
//
// DirectServer/DisableDirectSplit control "DNS follows route": when the resolver
// above is reached through the exit node (Detour="proxy"), domains that egress
// DIRECT are instead resolved by DirectServer — dialed direct — so domestic
// destinations get domestic answers instead of the exit region's CDN edges.
type DNSConfig struct {
	Servers  []DNSServer `json:"servers"`
	Rules    []DNSRule   `json:"rules"`
	Final    string      `json:"final,omitempty"`
	Strategy string      `json:"strategy,omitempty"` // "" | prefer_ipv4 | prefer_ipv6 | ipv4_only | ipv6_only
	// DirectServer resolves direct-routed domains; "" = 223.5.5.5. Accepts
	// "ip", "ip:port" or a hostname (an IP is strongly preferred — a hostname
	// resolver has to be reachable before any name can be resolved).
	DirectServer string `json:"direct_server,omitempty"`
	// DisableDirectSplit opts out of the split entirely: every domain, direct or
	// proxied, is resolved by the servers above. Domestic sites get overseas CDN
	// answers — only set this if you know why you want it.
	DisableDirectSplit bool `json:"disable_direct_split,omitempty"`
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
