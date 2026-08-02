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

// SubscriptionPublic is a subscription as the wire sees it: everything needed to
// display and manage one, and none of the credentials.
//
// A subscription URL *is* a credential — anyone holding it can pull the whole node
// list, and airports often key the account to it. The same is true of pasted node
// text, of a `via` proxy URL that can embed user:pass, and of each node's outbound
// (uuid / password / reality keys). None of it has any use in a browser: the
// console displays names and counts, and applying or refreshing happens by id.
//
// So they are write-only, exactly like a password field: settable, never readable
// back. internal/endpoints already treats WireGuard secrets this way; this type
// closes the same hole for subscriptions.
type SubscriptionPublic struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Source     string       `json:"source"`      // masked origin, e.g. "https://***.sbs/***"
	HasURL     bool         `json:"has_url"`     // fetched from a URL…
	HasContent bool         `json:"has_content"` // …or pasted
	HasVia     bool         `json:"has_via"`     // fetched through a proxy
	UserAgent  string       `json:"user_agent,omitempty"`
	NodeCount  int          `json:"node_count"`
	Nodes      []NodePublic `json:"nodes,omitempty"`
	UpdatedAt  string       `json:"updated_at,omitempty"`
	LastError  string       `json:"last_error,omitempty"`
	Applied    bool         `json:"applied,omitempty"`
}

// SubscriptionExport is one subscription's origin, handed back to an admin who
// explicitly asked for it — enough to recreate it on another gateway with
// `sub add` / `sub import`, and nothing more.
//
// The counterpart of SubscriptionPublic, not a replacement for it: Public is the
// shape everything sees by default and stays credential-free unconditionally,
// while this one is only ever produced by GET /api/subscriptions/{id}/export.
// Nodes are deliberately absent — recreating a subscription re-fetches them, so
// shipping every uuid / password / reality key would widen the exposure for
// nothing.
type SubscriptionExport struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url,omitempty"`
	Content   string `json:"content,omitempty"` // pasted node text, when there is no URL
	UserAgent string `json:"user_agent,omitempty"`
	Via       string `json:"via,omitempty"`
}

// NodePublic identifies a node without carrying the secret that dials it.
type NodePublic struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
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
	ID     string `json:"id"`    // sha256(match|value|action|node)[:12], idempotent
	Match  string `json:"match"` // domain | domain_suffix | keyword | regex | ip_cidr
	Value  string `json:"value"`
	Action string `json:"action"`           // legacy/wire: direct|proxy|block|node (mirrors Egress)
	Egress string `json:"egress,omitempty"` // none|direct|proxy|block|node
	Permit *bool  `json:"permit,omitempty"` // nil ⇒ derive from Action/Egress (compat)
	Node   string `json:"node,omitempty"`   // target outbound tag (required when egress==node)
	Pack   string `json:"pack,omitempty"`   // optional named pack; metadata only
	// Note is free text carried with the rule. It exists so a client's request to
	// permit something can travel as a *disabled* rule with its reason attached —
	// approval is then the admin enabling it, and no second store is needed for
	// "pending requests".
	Note    string `json:"note,omitempty"`
	Enabled bool   `json:"enabled"`
}

// PackRequestPrefix marks a pack that is a client's pending request rather than a
// curated policy pack: pack="request:<username>".
const PackRequestPrefix = "request:"

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
	PackExitMixed    = "mixed"    // per-rule egress (some direct, some Overseas/proxy)
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

// PermitQuarantineResult is the false-positive recovery response: the entry is
// gone from quarantine and present on Permit so Strict default-deny does not
// immediately re-block the same dial.
type PermitQuarantineResult struct {
	Quarantine []QuarantineEntry `json:"quarantine"`
	Permitted  struct {
		Type  string `json:"type"` // "domain" | "ip"
		Value string `json:"value"`
	} `json:"permitted"`
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

	// Query-level DNS observation. A DGA sweep is mostly NXDOMAIN and a DNS
	// tunnel encodes payload into names, so neither ever becomes a connection the
	// connection-side detectors could see. Counted in fixed windows; set a
	// threshold to 0 to ignore that signal.
	QueryWindowSec  int `json:"query_window_s,omitempty"`
	QueryNXBurst    int `json:"query_nxdomain_burst,omitempty"` // NXDOMAIN answers per client per window
	QueryParentRate int `json:"query_parent_rate,omitempty"`    // queries under one parent per window
	QueryOddTypeAt  int `json:"query_odd_type_at,omitempty"`    // TXT/NULL/ANY queries under one parent

	// DNSBypassDetect reports clients that resolve through a public DoH/DoT
	// service instead of this gateway — their names never reach our resolver and
	// the domain-based Permit gate only ever sees an IP.
	DNSBypassDetect bool `json:"dns_bypass_detect"`
	// DNSBypassReAlertSec is the per-endpoint cooldown. A client configured for
	// public DoH keeps using it, so without one the finding repeats per
	// connection — 614 of them in an hour on a real box.
	DNSBypassReAlertSec int `json:"dns_bypass_realert_s,omitempty"`
	// RouteWatchSec polls the host routing table for routes that appeared after
	// the tunnel came up and can carry traffic around it (TunnelVision shape).
	// 0 disables. Observation only — nothing is enforced.
	RouteWatchSec int `json:"route_watch_s,omitempty"`
	// RouteWatchHostRoutes also reports /32 and /128 routes. Off by default: the
	// data plane installs one per direct dial, so this trades a finding per
	// connection for coverage of a host-route hijack.
	RouteWatchHostRoutes bool `json:"route_watch_host_routes,omitempty"`

	// JA4Enabled records the TLS client fingerprint of every sniffed connection
	// and reports stacks this machine has not used before. JA4LearnMinutes is the
	// baseline window: reporting "unknown hash" from a cold start would fire on
	// every browser update, so nothing is reported until it closes.
	JA4Enabled      bool `json:"ja4_enabled"`
	JA4LearnMinutes int  `json:"ja4_learn_minutes,omitempty"`

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
	Builtin   []string          `json:"builtin,omitempty"`
	Domains   []string          `json:"domains,omitempty"`
	IPs       []string          `json:"ips,omitempty"`
	Processes []string          `json:"processes,omitempty"`
	Devices   []string          `json:"devices,omitempty"`
	Keywords  []string          `json:"keywords,omitempty"`
	Regexes   []string          `json:"regexes,omitempty"`
	// Notes are optional remarks keyed as "<dim>:<value>" (e.g. "ip:1.2.3.4").
	// Informational only — never consulted by the data plane.
	Notes map[string]string `json:"notes,omitempty"`
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
	Domains   []string          `json:"domains"`
	IPs       []string          `json:"ips"`
	Processes []string          `json:"processes"`
	Devices   []string          `json:"devices"`
	Notes     map[string]string `json:"notes,omitempty"`
}

// DirectList is the no-proxy / bypass snapshot (mirrors directlist.Rules).
type DirectList struct {
	Domains []string          `json:"domains"`
	IPs     []string          `json:"ips"`
	Notes   map[string]string `json:"notes,omitempty"`
}

// ProxyGroup is one user-defined group in a Profile / proxygroups config.
type ProxyGroup struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`   // select | urltest
	Filter string   `json:"filter"` // country | regex | manual
	Value  string   `json:"value,omitempty"`
	Nodes  []string `json:"nodes,omitempty"`
}

// ProxyFailover mirrors internal/proxygroups.Failover: how eagerly urltest
// groups re-elect a member, and whether a re-election kills live connections.
// Zero values mean "use the gateway default".
type ProxyFailover struct {
	ProbeIntervalSeconds         int  `json:"probe_interval_seconds,omitempty"`
	ToleranceMS                  int  `json:"tolerance_ms,omitempty"`
	IdleTimeoutSeconds           int  `json:"idle_timeout_seconds,omitempty"`
	InterruptExistingConnections bool `json:"interrupt_existing_connections"`
}

// ProxyScoring mirrors internal/proxyscore.Config: how urltest ranks members by
// observed real-traffic quality rather than probe latency alone. Zero values
// mean "use the gateway default", and the flag is Disabled rather than Enabled
// so an omitted block means scoring on with stock settings.
type ProxyScoring struct {
	Disabled bool `json:"disabled,omitempty"`

	// MinSamples is how many real outcomes a node needs before its score stops
	// being the neutral 100.
	MinSamples int `json:"min_samples,omitempty"`

	// Weights are relative, not percentages: the score divides by their sum.
	WeightReliability int `json:"weight_reliability,omitempty"`
	WeightLatency     int `json:"weight_latency,omitempty"`
	WeightThroughput  int `json:"weight_throughput,omitempty"`

	// Streak amplification: the Nth consecutive outcome counts N× the first,
	// capped at MaxStreak.
	RewardPerSuccess  int `json:"reward_per_success,omitempty"`
	PenaltyPerFailure int `json:"penalty_per_failure,omitempty"`
	MaxStreak         int `json:"max_streak,omitempty"`

	LatencyGoodMS int `json:"latency_good_ms,omitempty"`
	LatencyBadMS  int `json:"latency_bad_ms,omitempty"`

	ThroughputGoodKBps int `json:"throughput_good_kbps,omitempty"`

	// TieMarginPoints: score gaps smaller than this count as equal, and latency
	// breaks the tie.
	TieMarginPoints int `json:"tie_margin_points,omitempty"`

	BreakerFailures     int `json:"breaker_failures,omitempty"`
	BreakerDelaySeconds int `json:"breaker_delay_seconds,omitempty"`
	BreakerSuccesses    int `json:"breaker_successes,omitempty"`

	StaleHours int `json:"stale_hours,omitempty"`

	// BlackholeStreak: consecutive "handshake ok, we sent bytes, nothing came
	// back" connections that confirm a node as a blackhole. -1 turns the
	// detection off; 0 means unset and resolves to the default.
	BlackholeStreak int `json:"blackhole_streak,omitempty"`

	// StreamStallSec: mid-connection watchdog. After a proxied connection has
	// uploaded StreamStallMinUpload bytes and then produces no download for
	// this many seconds, the gateway kills the conn and demotes the member so
	// the client's retry lands elsewhere. Scoring alone only steers *new*
	// dials — Cursor-agent streams die while still open. 0 = unset (default
	// on); -1 disables.
	StreamStallSec       int `json:"stream_stall_sec,omitempty"`
	StreamStallMinUpload int `json:"stream_stall_min_upload,omitempty"`
	StreamStallMinAgeSec int `json:"stream_stall_min_age_sec,omitempty"`
}

// ProxyGroupsConfig mirrors internal/proxygroups.Config for wire/profile use.
type ProxyGroupsConfig struct {
	AutoCountry      bool          `json:"auto_country"`
	ExcludeCountries []string      `json:"exclude_countries"`
	Groups           []ProxyGroup  `json:"groups"`
	Failover         ProxyFailover `json:"failover"`
	Scoring          ProxyScoring  `json:"scoring"`
}

// ProxyScore is one member's live scoring view: the number, the three terms it
// came from, and the raw evidence behind each. The breakdown is the point — a
// bare score cannot answer "why is this node at 62", and the whole feature is
// supposed to be legible rather than another opaque auto-switch.
type ProxyScore struct {
	Tag   string  `json:"tag"`
	Score float64 `json:"score"`

	Reliability float64 `json:"reliability"`
	Latency     float64 `json:"latency_score"`
	Throughput  float64 `json:"throughput_score"`

	Samples    int  `json:"samples"`
	MinSamples int  `json:"min_samples"`
	Warming    bool `json:"warming"`

	OKStreak   int `json:"ok_streak"`
	FailStreak int `json:"fail_streak"`

	LatencyMS      int     `json:"latency_ms,omitempty"`
	ThroughputKBps float64 `json:"throughput_kbps,omitempty"`

	// Breaker is closed|open|half-open. Open means "demoted to last resort",
	// never "excluded" — a group that drops its unhealthy members can end up
	// with none at all.
	Breaker          string `json:"breaker"`
	BreakerRemaining int    `json:"breaker_remaining_seconds,omitempty"`
	Preferred        bool   `json:"preferred"`

	// Blackhole marks a node that completes handshakes and relays nothing back.
	// Reported separately from the score because a bare 0 reads as "very slow",
	// and the remedy differs: a slow node is still worth keeping.
	Blackhole       bool `json:"blackhole,omitempty"`
	BlackholeStreak int  `json:"blackhole_streak,omitempty"`

	LastOK    bool   `json:"last_ok"`
	LastErr   string `json:"last_err,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// ProxyScores is the /api/proxy-scores response: the per-member views plus the
// policy in force and the formula rendered with the live weights, so a client
// can explain a score without hard-coding the arithmetic.
type ProxyScores struct {
	Scores  []ProxyScore `json:"scores"`
	Config  ProxyScoring `json:"config"`
	Formula string       `json:"formula"`
	Enabled bool         `json:"enabled"`
}

// Node member status values for /api/node-overrides.
const (
	NodeStatusLive     = "live"
	NodeStatusDisabled = "disabled"
	NodeStatusJunk     = "junk"
)

// JunkNode is one airport info/redirect line filtered out of Auto by fingerprint.
type JunkNode struct {
	Tag      string `json:"tag"`
	Reason   string `json:"reason"`
	Server   string `json:"server,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// NodeMember is one applied subscription/exit node with its inject status.
type NodeMember struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol,omitempty"`
	Server   string `json:"server,omitempty"`
	Port     int    `json:"port,omitempty"`
	Status   string `json:"status"`           // live|disabled|junk
	Reason   string `json:"reason,omitempty"` // junk fingerprint, when status=junk
}

// NodeOverrides is the /api/node-overrides response: operator disables, auto-
// detected junk, and the full applied-node table for CLI/UI.
type NodeOverrides struct {
	Disabled []string     `json:"disabled"`
	Junk     []JunkNode   `json:"junk"`
	Nodes    []NodeMember `json:"nodes"`
}

// NodeOverridesPatch is PUT/PATCH /api/node-overrides. Set Disabled for a full
// replace; or Disable/Enable for a single tag. Exactly one form should be set.
type NodeOverridesPatch struct {
	Disabled *[]string `json:"disabled,omitempty"`
	Disable  string    `json:"disable,omitempty"`
	Enable   string    `json:"enable,omitempty"`
}

// NodeTagBody is POST /api/nodes/disable|enable.
type NodeTagBody struct {
	Tag string `json:"tag"`
}

// Blacklist is the egress deny-list snapshot: destinations that are REJECTED
// even if an allow rule (whitelist / allow rule-set) would otherwise permit
// them. Domains match domain_suffix, Keywords match domain_keyword, Regexes
// match domain_regex, IPs match ip_cidr. Injected as reject rules above the
// allows so a blacklisted target is dropped first.
type Blacklist struct {
	Domains  []string          `json:"domains"`
	Keywords []string          `json:"keywords"`
	Regexes  []string          `json:"regexes"`
	IPs      []string          `json:"ips"`
	Notes    map[string]string `json:"notes,omitempty"`
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

// InboundAuth is the optional credential set required on the mixed proxy inbound
// (:21584). Empty = auth disabled = the inbound is open.
//
// Users is the current shape (sing-box's mixed inbound accepts many). Username /
// Password are the original single-pair fields, kept so an existing inbound.json
// still loads; the store migrates them into Users on first read.
type InboundAuth struct {
	Users    []ProxyCredential `json:"users,omitempty"`
	Username string            `json:"username,omitempty"` // deprecated: migrated into Users
	Password string            `json:"password,omitempty"` // deprecated: migrated into Users
}

// Credentials returns every credential, folding in the deprecated single pair so
// an inbound.json written by an older build keeps working.
func (a InboundAuth) Credentials() []ProxyCredential {
	out := make([]ProxyCredential, 0, len(a.Users)+1)
	seen := map[string]bool{}
	for _, c := range a.Users {
		if c.Username == "" || c.Password == "" || seen[c.Username] {
			continue
		}
		seen[c.Username] = true
		out = append(out, c)
	}
	if a.Username != "" && a.Password != "" && !seen[a.Username] {
		out = append(out, ProxyCredential{Username: a.Username, Password: a.Password})
	}
	return out
}

// ProxyCredential is one username/password accepted by the proxy inbound.
//
// Stored in the clear, unavoidably: sing-box validates it itself, so it has to be
// in the generated config. This is why it is a different secret from an account
// password, which is only ever stored as an argon2id hash.
type ProxyCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// User is a console account, with every secret stripped for the wire.
type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	Role         string   `json:"role"` // admin | user
	Disabled     bool     `json:"disabled,omitempty"`
	HasProxyCred bool     `json:"has_proxy_cred"` // has a proxy-inbound password
	APIKeys      []APIKey `json:"api_keys,omitempty"`
	CreatedAt    string   `json:"created_at"`
	LastLoginAt  string   `json:"last_login_at,omitempty"`
	// SessionEpoch is carried so a session token can be bound to it: a password
	// change bumps the epoch and every token minted under the old one stops
	// authenticating. Not secret — it is a counter — and not part of the console's
	// display, hence omitempty.
	SessionEpoch int `json:"session_epoch,omitempty"`
	// PasswordGenerated is true while the account's password is the random one
	// `install` created and told nobody. Setting a password then needs no current
	// password, because there is no secret for that check to protect; the console
	// uses this to label the field "set" rather than "change".
	PasswordGenerated bool `json:"password_generated,omitempty"`
}

// APIKey is a non-interactive credential's metadata. The key itself is shown once
// at creation and only its hash is kept.
type APIKey struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Prefix     string `json:"prefix"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// APIKeyCreated is the one and only response that carries the raw key.
type APIKeyCreated struct {
	APIKey
	Key string `json:"key"`
}

// LoginRequest is the POST /api/auth/login body.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Session is what the console learns about itself after logging in.
type Session struct {
	User      User   `json:"user"`
	ExpiresAt string `json:"expires_at"`
}

// AuthState tells a caller what it may do: create the first admin, log in, or
// (only if an admin opened it) register.
type AuthState struct {
	NeedsBootstrap    bool  `json:"needs_bootstrap"`
	AllowRegistration bool  `json:"allow_registration"`
	Authenticated     bool  `json:"authenticated"`
	User              *User `json:"user,omitempty"`
	// NeedsBootstrapCode reports that this caller is not on the gateway's own
	// machine, so claiming it also takes the one-time code from the log. The UI
	// has to know before showing the form: on a cloud gateway — the normal case
	// for a remote console — a form without that field can only ever 403.
	NeedsBootstrapCode bool `json:"needs_bootstrap_code,omitempty"`
	// GatewayID is a stable, non-secret fingerprint of this installation. A stored
	// CLI credential carries the id it was minted against, so a 401 can say "this
	// gateway was reinstalled" instead of leaving you to guess.
	GatewayID string `json:"gateway_id,omitempty"`
}

// ConsoleTicket is a single-use token that buys one browser session, for a
// caller that holds an API key but needs a *cookie* (the desktop shell opening
// the console in its webview).
type ConsoleTicket struct {
	Ticket     string `json:"ticket"`
	URL        string `json:"url"`
	ExpiresInS int    `json:"expires_in_s"`
}

// PatchUserRequest is the PATCH /api/users/{id} body. Every field is optional; a
// nil one is left untouched. An empty (non-nil) ProxyPassword removes proxy
// access — which is why these are pointers and not plain strings.
type PatchUserRequest struct {
	Role          *string `json:"role,omitempty"`
	Disabled      *bool   `json:"disabled,omitempty"`
	Password      *string `json:"password,omitempty"`
	ProxyPassword *string `json:"proxy_password,omitempty"`
	// CurrentPassword is required when changing your *own* password, and ignored
	// when an admin resets somebody else's (they do not know it, and requiring it
	// would make a reset impossible).
	//
	// Without it a stolen session was not merely a session: the thief could set a
	// password of their own and lock the owner out of an account they still owned.
	CurrentPassword *string `json:"current_password,omitempty"`
}

// AuthSettings are the registry-wide auth knobs (admin-writable at runtime).
type AuthSettings struct {
	AllowRegistration bool `json:"allow_registration"`
}

// TUNConfig tunes the tun inbound the gateway builds in TUN mode. Only takes
// effect when the capture mode is "tun"; otherwise the values are inert.
type TUNConfig struct {
	Stack          string   `json:"stack"`                     // system | gvisor | mixed (default gvisor)
	MTU            int      `json:"mtu"`                       // 0 = auto (omit "mtu")
	StrictRoute    bool     `json:"strict_route"`              // default true
	AutoRedirect   bool     `json:"auto_redirect"`             // Linux: nftables redirect; captures Docker/containerd bridge egress (default true)
	Address        []string `json:"address,omitempty"`         // TUN interface CIDRs; empty = DefaultTUNAddresses (198.18/30, avoids Docker 172.16/12)
	ExcludePackage []string `json:"exclude_package,omitempty"` // Android: packages routed AROUND the tun
	IncludePackage []string `json:"include_package,omitempty"` // Android: only these packages routed INTO the tun
	// There is deliberately no ExcludeProcess: sing-box's tun inbound has no such
	// option, so the field this type used to carry was stored, echoed back by
	// `tun get`, and never injected anywhere — a setting that reads as applied
	// and isn't. Keeping a process out of the tunnel is a Route decision, not a
	// capture one: use a custom rule (process → direct) or no-proxy.
}

// DefaultTUNAddresses are used when TUNConfig.Address is empty. 198.18.0.0/15 is
// the RFC 2544 benchmarking range — Clash/sing-box convention — and sits outside
// Docker/CNI's usual 172.16/12 allocations so the TUN /30 does not collide with
// a compose network.
var DefaultTUNAddresses = []string{"198.18.0.1/30", "fdfe:dcba:9876::1/126"}

// The proxy inbound's built-in listen point, used when InboundListen leaves a
// field at its zero value. Both are what the seeded configs/config.json declares.
const (
	DefaultInboundListen = "127.0.0.1"
	DefaultInboundPort   = 21584
)

// InboundListen is where the mixed (socks/http) proxy inbound listens.
//
// Zero values mean "whatever the base config says", which is how every existing
// machine keeps behaving exactly as before: this store did not exist until the
// settings sweep, and the port was reachable only by hand-editing the config
// file the docs say not to hand-edit.
//
// Deliberately NOT part of InboundAuth: credentials are derived from the user
// registry and rewritten on every password change, so a combined struct would
// make "change a password" a chance to silently reset the listen point — the
// shape of the POST-drops-fields bug in CLAUDE.md. Deliberately NOT part of a
// profile/posture snapshot either: this is machine plumbing, not policy, and
// activating last week's profile must not move the port out from under the
// clients pointed at it.
type InboundListen struct {
	Listen string `json:"listen,omitempty"` // "" = DefaultInboundListen
	Port   int    `json:"port,omitempty"`   // 0  = DefaultInboundPort
}

// Resolved fills the zero values with the defaults.
func (l InboundListen) Resolved() InboundListen {
	if l.Listen == "" {
		l.Listen = DefaultInboundListen
	}
	if l.Port == 0 {
		l.Port = DefaultInboundPort
	}
	return l
}

// InboundListenState is what GET/PUT /api/inbound answer with.
//
// Listen and Resolved are both present on purpose: a client editing the setting
// needs to know which fields the operator actually chose (so it can leave the
// others blank rather than freezing today's defaults into the store), while a
// client merely displaying the address needs the resolved one.
type InboundListenState struct {
	Listen   InboundListen  `json:"listen"`
	Resolved InboundListen  `json:"resolved"`
	Revert   *InboundRevert `json:"revert,omitempty"`
}

// InboundRevert is the pending dead-man's switch: unless it is confirmed, the
// gateway goes back to To in InSeconds.
type InboundRevert struct {
	To        InboundListen `json:"to"`
	InSeconds int           `json:"in_seconds"`
}

// RetentionRule is one lumberjack-backed file's rotation policy.
type RetentionRule struct {
	// MaxSizeMB rotates past this size. 0 = the built-in default; -1 disables
	// rotation entirely (the `--log-max-size 0` spelling, which cannot be 0 here
	// because 0 already means "unset").
	MaxSizeMB int `json:"max_size_mb,omitempty"`
	// MaxBackups is how many rotated generations to keep. 0 = built-in default.
	MaxBackups int `json:"max_backups,omitempty"`
	// MaxAgeDays deletes rotated files older than this. 0 = keep by count only.
	MaxAgeDays int `json:"max_age_days,omitempty"`
	// Compress gzips rotated generations. A pointer because the default is *on*,
	// and a plain bool's zero value is off: a store that has never been written,
	// or a client that sends only max_size_mb, would silently turn compression
	// off — a setting nobody touched changing itself. nil = the default.
	Compress *bool `json:"compress,omitempty"`
}

// CompressOr resolves the tri-state against the caller's default.
func (r RetentionRule) CompressOr(def bool) bool {
	if r.Compress == nil {
		return def
	}
	return *r.Compress
}

// Retention is how much of the gateway's own output is kept on disk.
//
// Both halves used to exist only as `serve` flags, which meant that once the
// gateway was installed as a system service they were frozen into the launchd
// plist / systemd unit: changing them required an edit-and-reinstall, and a
// plain re-install (the documented upgrade path) silently reverted them. Same
// failure that produced internal/modecfg — so, same answer: a store.
type Retention struct {
	Log     RetentionRule `json:"log"`     // the daemon log (<data>/serve.log)
	History RetentionRule `json:"history"` // per-connection history (<data>/history.jsonl)
}

// Defaults is every domain's built-in configuration, served read-only so a
// client can offer "restore defaults" and annotate blank fields without
// hard-coding a second copy of the numbers. A UI that computes its own defaults
// is a second source of truth that drifts the moment one side changes.
type Defaults struct {
	TUN       TUNConfig       `json:"tun"`
	DNS       DNSConfig       `json:"dns"`
	Detection DetectionConfig `json:"detection"`
	Retention Retention       `json:"retention"`
	Inbound   InboundListen   `json:"inbound"`
	Failover  ProxyFailover   `json:"failover"`
	Scoring   ProxyScoring    `json:"scoring"`
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

// ProxyGenRequest asks for a one-click self-hosted exit: a server config plus
// the matching client node. Type is one of proxygen.Protocols.
type ProxyGenRequest struct {
	Type   string `json:"type"`
	Server string `json:"server"`         // address the client dials (required)
	Port   int    `json:"port,omitempty"` // default 443
	SNI    string `json:"sni,omitempty"`  // TLS/Reality SNI
	Name   string `json:"name,omitempty"` // node name
}

// ProxyGenResult is the generated pair plus the commands that deploy it. Both
// halves come from one generation: the keys in Server are the keys in Client.
type ProxyGenResult struct {
	Server        map[string]any `json:"server"` // sing-box server config
	Client        map[string]any `json:"client"` // Clash node dict, importable as-is
	Share         string         `json:"share,omitempty"`
	GenCommand    string         `json:"gen_command"`    // the equivalent CLI call
	InstallScript string         `json:"install_script"` // paste on the exit host
}

// ErrorResponse is the standard error envelope.
type ErrorResponse struct {
	Error string `json:"error"`
}

// HistoryRecord is one completed connection, as /api/history returns it.
//
// The field names are short because internal/history appends one of these per
// connection and the file is measured in tens of megabytes. They are declared here
// rather than left to callers because they *were* left to callers: `history ls`
// read closed_at / host / upload / download / outbound out of a map[string]any,
// none of which exist, so it printed the right number of rows with nothing in them
// and <nil> where the byte counts go. --json looked perfect, because that path
// never touches a name. With a type, a wrong name is a compile error.
type HistoryRecord struct {
	Time     string `json:"t"`
	Host     string `json:"h"`
	Dest     string `json:"d,omitempty"`
	Process  string `json:"p,omitempty"`
	User     string `json:"usr,omitempty"`
	Outbound string `json:"o,omitempty"`
	Up       int64  `json:"u"`
	Down     int64  `json:"dn"`
	Denied   bool   `json:"x,omitempty"`
	Level    string `json:"l,omitempty"`
	// DurationMS is how long the connection was open — with the byte counts, this is
	// what identifies a stalled connection (open a long time, moved nothing).
	DurationMS int64 `json:"ms,omitempty"`
	DNSMs      int64 `json:"dns_ms,omitempty"`
	ConnectMs  int64 `json:"connect_ms,omitempty"`
	TLSMs      int64 `json:"tls_ms,omitempty"`
}

// HistoryPage is one page of history: Total counts every match, Items only this page.
type HistoryPage struct {
	Total int             `json:"total"`
	Items []HistoryRecord `json:"items"`
}
