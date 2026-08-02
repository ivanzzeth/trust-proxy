// Policy/runtime surface of the SDK: everything the console can do, so the CLI
// (and any script) can do it too. One thin method per endpoint — the shapes are
// the wire types in pkg/apitypes, not a second model.
package client

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
	"github.com/ivanzzeth/trust-proxy/pkg/clash"
)

// ---- status -------------------------------------------------------------

// Status returns the gateway's runtime summary (mode, node count, posture…).
func (c *Client) Status() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/status", nil, &out)
	return out, err
}

// EffectiveRules returns the derived L0..L4 view of what the data plane will do.
func (c *Client) EffectiveRules() ([]apitypes.RuleView, error) {
	var out []apitypes.RuleView
	err := c.do(http.MethodGet, "/api/effective-rules", nil, &out)
	return out, err
}

// ---- ACL lists (Permit / Deny / No-Proxy) -------------------------------

// listKind identifies the three list stores, which share one wire shape.
type listKind string

const (
	ListPermit  listKind = "whitelist"  // Permit axis: may leave the network
	ListDeny    listKind = "blacklist"  // hard deny, beats Permit
	ListNoProxy listKind = "directlist" // Route axis only: egress direct
)

// List returns one ACL list.
func (c *Client) List(kind listKind) (apitypes.ACLList, error) {
	var out apitypes.ACLList
	err := c.do(http.MethodGet, "/api/"+string(kind), nil, &out)
	return out, err
}

// listEntry is the shared {type,value,note?} mutation body.
type listEntry struct {
	Type  string  `json:"type"`
	Value string  `json:"value"`
	Note  *string `json:"note,omitempty"`
}

// AddListEntry adds one entry. typ is domain|ip|process|device (per list).
// Optional note sets/updates the remark; omit (nil) to leave an existing
// remark alone on re-add. Pass a pointer to "" to clear.
func (c *Client) AddListEntry(kind listKind, typ, value string, note ...string) (apitypes.ACLList, error) {
	body := listEntry{Type: typ, Value: value}
	if len(note) > 0 {
		n := note[0]
		body.Note = &n
	}
	var out apitypes.ACLList
	err := c.do(http.MethodPost, "/api/"+string(kind), body, &out)
	return out, err
}

// DeleteListEntry removes one entry.
func (c *Client) DeleteListEntry(kind listKind, typ, value string) (apitypes.ACLList, error) {
	var out apitypes.ACLList
	err := c.do(http.MethodDelete, "/api/"+string(kind), listEntry{Type: typ, Value: value}, &out)
	return out, err
}

// ---- custom rules + policy packs ---------------------------------------

// CustomRules returns the ordered custom rule list (L4 priority order).
func (c *Client) CustomRules() ([]apitypes.CustomRule, error) {
	var out []apitypes.CustomRule
	err := c.do(http.MethodGet, "/api/customrules", nil, &out)
	return out, err
}

// AddCustomRule appends a rule and returns the resulting ordered list.
func (c *Client) AddCustomRule(r apitypes.CustomRule) ([]apitypes.CustomRule, error) {
	var out []apitypes.CustomRule
	err := c.do(http.MethodPost, "/api/customrules", r, &out)
	return out, err
}

// PatchCustomRule updates the set fields of one rule.
func (c *Client) PatchCustomRule(id string, req apitypes.PatchCustomRuleRequest) ([]apitypes.CustomRule, error) {
	var out []apitypes.CustomRule
	err := c.do(http.MethodPatch, "/api/customrules/"+url.PathEscape(id), req, &out)
	return out, err
}

// DeleteCustomRule removes one rule.
func (c *Client) DeleteCustomRule(id string) error {
	return c.do(http.MethodDelete, "/api/customrules/"+url.PathEscape(id), nil, nil)
}

// MoveCustomRule shifts a rule's priority: dir<0 up, dir>0 down.
func (c *Client) MoveCustomRule(id string, dir int) ([]apitypes.CustomRule, error) {
	var out []apitypes.CustomRule
	err := c.do(http.MethodPost, "/api/customrules/"+url.PathEscape(id)+"/move", map[string]int{"dir": dir}, &out)
	return out, err
}

// MoveCustomRuleTop promotes a rule to index 0 (highest first-match priority).
// Not a pin — later adds/moves can push it down again.
func (c *Client) MoveCustomRuleTop(id string) ([]apitypes.CustomRule, error) {
	var out []apitypes.CustomRule
	err := c.do(http.MethodPost, "/api/customrules/"+url.PathEscape(id)+"/move", map[string]string{"to": "top"}, &out)
	return out, err
}

// PackCatalog lists the curated one-click policy packs.
func (c *Client) PackCatalog() ([]apitypes.PackPreset, error) {
	var out []apitypes.PackPreset
	err := c.do(http.MethodGet, "/api/customrules/packs/catalog", nil, &out)
	return out, err
}

// ApplyPack imports a catalog pack by name.
func (c *Client) ApplyPack(name string) (apitypes.PackApplyResult, error) {
	var out apitypes.PackApplyResult
	err := c.do(http.MethodPost, "/api/customrules/packs/apply", map[string]string{"catalog": name}, &out)
	return out, err
}

// PatchPack enables/disables every rule of a pack.
func (c *Client) PatchPack(name string, enabled bool) ([]apitypes.CustomRule, error) {
	var out []apitypes.CustomRule
	err := c.do(http.MethodPatch, "/api/customrules/packs/"+url.PathEscape(name), map[string]bool{"enabled": enabled}, &out)
	return out, err
}

// DeletePack removes a pack's rules (and subtracts its rule-set roles).
func (c *Client) DeletePack(name string) error {
	return c.do(http.MethodDelete, "/api/customrules/packs/"+url.PathEscape(name), nil, nil)
}

// ---- rule sets ----------------------------------------------------------

// RuleSets lists the imported sing-box rule sets.
func (c *Client) RuleSets() ([]apitypes.RuleSet, error) {
	var out []apitypes.RuleSet
	err := c.do(http.MethodGet, "/api/rulesets", nil, &out)
	return out, err
}

// RuleSetCatalog lists the public rule sets available for one-click import.
func (c *Client) RuleSetCatalog() ([]apitypes.RuleSetCatalogEntry, error) {
	var out []apitypes.RuleSetCatalogEntry
	err := c.do(http.MethodGet, "/api/rulesets/catalog", nil, &out)
	return out, err
}

// AddRuleSet imports a rule set (by catalog tag or explicit URL/path).
func (c *Client) AddRuleSet(req apitypes.AddRuleSetRequest) ([]apitypes.RuleSet, error) {
	var out []apitypes.RuleSet
	err := c.do(http.MethodPost, "/api/rulesets", req, &out)
	return out, err
}

// PatchRuleSet toggles enabled / changes the role of one rule set.
func (c *Client) PatchRuleSet(tag string, req apitypes.PatchRuleSetRequest) ([]apitypes.RuleSet, error) {
	var out []apitypes.RuleSet
	err := c.do(http.MethodPatch, "/api/rulesets/"+url.PathEscape(tag), req, &out)
	return out, err
}

// DeleteRuleSet removes one rule set.
func (c *Client) DeleteRuleSet(tag string) error {
	return c.do(http.MethodDelete, "/api/rulesets/"+url.PathEscape(tag), nil, nil)
}

// RuleSetRules returns the decoded contents of one rule set.
func (c *Client) RuleSetRules(tag string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/rulesets/"+url.PathEscape(tag)+"/rules", nil, &out)
	return out, err
}

// ---- profiles -----------------------------------------------------------

// Profiles lists saved configuration snapshots.
func (c *Client) Profiles() ([]apitypes.Profile, error) {
	var out []apitypes.Profile
	err := c.do(http.MethodGet, "/api/profiles", nil, &out)
	return out, err
}

// SaveProfile snapshots the current policy under name.
func (c *Client) SaveProfile(name string) (apitypes.Profile, error) {
	var out apitypes.Profile
	err := c.do(http.MethodPost, "/api/profiles", map[string]string{"name": name}, &out)
	return out, err
}

// ActivateProfile applies a snapshot in one atomic rebuild.
func (c *Client) ActivateProfile(id string) (apitypes.Profile, error) {
	var out apitypes.Profile
	err := c.do(http.MethodPost, "/api/profiles/"+url.PathEscape(id)+"/activate", nil, &out)
	return out, err
}

// DeleteProfile removes a snapshot.
func (c *Client) DeleteProfile(id string) error {
	return c.do(http.MethodDelete, "/api/profiles/"+url.PathEscape(id), nil, nil)
}

// ---- detection tuning + quarantine --------------------------------------

// DetectionConfig returns the engine's tunable thresholds.
func (c *Client) DetectionConfig() (apitypes.DetectionConfig, error) {
	var out apitypes.DetectionConfig
	err := c.do(http.MethodGet, "/api/detection-config", nil, &out)
	return out, err
}

// SetDetectionConfig replaces the thresholds and pushes them into the running
// engine. A rejected document leaves the engine on its previous settings.
func (c *Client) SetDetectionConfig(cfg apitypes.DetectionConfig) (apitypes.DetectionConfig, error) {
	var out apitypes.DetectionConfig
	err := c.do(http.MethodPut, "/api/detection-config", cfg, &out)
	return out, err
}

// DNSQueryStats returns query-level activity: totals, NXDOMAIN share and the
// busiest parent domains. This is where a DGA sweep or a DNS tunnel shows up —
// neither ever becomes a connection.
func (c *Client) DNSQueryStats(top int) (map[string]any, error) {
	v := url.Values{}
	if top > 0 {
		v.Set("top", strconv.Itoa(top))
	}
	var out map[string]any
	err := c.do(http.MethodGet, "/api/dns-queries/stats?"+v.Encode(), nil, &out)
	return out, err
}

// Fingerprints lists the TLS client stacks this gateway has seen, plus whether
// the baseline window is still open.
func (c *Client) Fingerprints(limit int) (map[string]any, error) {
	v := url.Values{}
	if limit > 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	var out map[string]any
	err := c.do(http.MethodGet, "/api/fingerprints?"+v.Encode(), nil, &out)
	return out, err
}

// NetworkState returns the host routing / interface picture the gateway watches
// for tunnel bypasses (TunnelVision-style routes, LocalNet scope).
func (c *Client) NetworkState() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/netcheck", nil, &out)
	return out, err
}

// Quarantine lists what the gateway blocked by itself (threat intel / exfil
// disposal). Separate from the deny list, which is operator policy.
func (c *Client) Quarantine() ([]apitypes.QuarantineEntry, error) {
	var out []apitypes.QuarantineEntry
	err := c.do(http.MethodGet, "/api/quarantine", nil, &out)
	return out, err
}

// ReleaseQuarantine removes one entry ("this was a false positive").
func (c *Client) ReleaseQuarantine(value string) ([]apitypes.QuarantineEntry, error) {
	var out []apitypes.QuarantineEntry
	err := c.do(http.MethodDelete, "/api/quarantine", map[string]any{"value": value}, &out)
	return out, err
}

// ClearQuarantine releases everything.
func (c *Client) ClearQuarantine() ([]apitypes.QuarantineEntry, error) {
	var out []apitypes.QuarantineEntry
	err := c.do(http.MethodDelete, "/api/quarantine", map[string]any{"all": true}, &out)
	return out, err
}

// PermitQuarantine releases one false-positive AND adds it to Permit (whitelist).
// Release alone only lifts the L1 floor; without Permit, Strict still blocks the
// dial and it looks like the ban never left.
func (c *Client) PermitQuarantine(value string) (apitypes.PermitQuarantineResult, error) {
	var out apitypes.PermitQuarantineResult
	err := c.do(http.MethodPost, "/api/quarantine/permit", map[string]any{"value": value}, &out)
	return out, err
}

// ---- resolver / egress knobs -------------------------------------------

// DNS returns the resolver policy.
func (c *Client) DNS() (apitypes.DNSConfig, error) {
	var out apitypes.DNSConfig
	err := c.do(http.MethodGet, "/api/dns", nil, &out)
	return out, err
}

// SetDNS replaces the resolver policy (validated + rolled back on failure).
func (c *Client) SetDNS(d apitypes.DNSConfig) (apitypes.DNSConfig, error) {
	var out apitypes.DNSConfig
	err := c.do(http.MethodPut, "/api/dns", d, &out)
	return out, err
}

// Final returns the catch-all egress for permitted-but-unrouted traffic.
func (c *Client) Final() (apitypes.FinalConfig, error) {
	var out apitypes.FinalConfig
	err := c.do(http.MethodGet, "/api/final", nil, &out)
	return out, err
}

// SetFinal sets the catch-all egress.
func (c *Client) SetFinal(outbound string) (apitypes.FinalConfig, error) {
	var out apitypes.FinalConfig
	err := c.do(http.MethodPut, "/api/final", apitypes.FinalConfig{Outbound: outbound}, &out)
	return out, err
}

// Posture returns the active Strict|Split posture.
func (c *Client) Posture() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/posture", nil, &out)
	return out, err
}

// SetPosture switches Strict|Split (slot swap happens server-side).
func (c *Client) SetPosture(active string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPut, "/api/posture", map[string]string{"active": active}, &out)
	return out, err
}

// ---- capture mode + routing mode ---------------------------------------

// Mode returns the capture mode (manual|system|tun) and any pending revert.
func (c *Client) Mode() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/mode", nil, &out)
	return out, err
}

// SetMode switches the capture mode. guardSeconds > 0 arms the dead-man's
// switch: the mode reverts unless ConfirmMode is called in time — the thing that
// keeps a remote TUN switch from locking you out.
func (c *Client) SetMode(mode string, guardSeconds int) (map[string]any, error) {
	var out map[string]any
	body := map[string]any{"mode": mode}
	if guardSeconds > 0 {
		body["guard_seconds"] = guardSeconds
	}
	err := c.do(http.MethodPost, "/api/mode", body, &out)
	return out, err
}

// ConfirmMode cancels a pending guarded revert.
func (c *Client) ConfirmMode() error {
	return c.do(http.MethodPost, "/api/mode/confirm", nil, nil)
}

// ClashMode returns the routing mode (Rule|Global).
func (c *Client) ClashMode() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/clash-mode", nil, &out)
	return out, err
}

// SetClashMode switches Rule|Global with no rebuild. Direct is refused by the
// backend (it would bypass the gateway entirely).
func (c *Client) SetClashMode(mode string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPut, "/api/clash-mode", map[string]string{"mode": mode}, &out)
	return out, err
}

// AutoBlock toggles automatic disconnection on threat-intel hits.
func (c *Client) AutoBlock(enabled bool) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPost, "/api/autoblock", map[string]bool{"enabled": enabled}, &out)
	return out, err
}

// ---- inbound / tun / groups / endpoints --------------------------------

// TUN returns the TUN inbound's advanced options.
func (c *Client) TUN() (apitypes.TUNConfig, error) {
	var out apitypes.TUNConfig
	err := c.do(http.MethodGet, "/api/tun", nil, &out)
	return out, err
}

// SetTUN replaces the TUN options (takes effect in tun mode).
func (c *Client) SetTUN(t apitypes.TUNConfig) (apitypes.TUNConfig, error) {
	var out apitypes.TUNConfig
	err := c.do(http.MethodPut, "/api/tun", t, &out)
	return out, err
}

// InboundListen returns where the proxy inbound listens, both as stored (zero
// fields = no opinion) and resolved, plus a pending guarded revert if one is
// running.
func (c *Client) InboundListen() (apitypes.InboundListenState, error) {
	var out apitypes.InboundListenState
	err := c.do(http.MethodGet, "/api/inbound", nil, &out)
	return out, err
}

// SetInboundListen moves the proxy inbound. guardSeconds > 0 arms a dead-man's
// switch: unless ConfirmInboundListen lands first, the gateway reverts. That is
// not optional politeness — a bad address does not fail, it succeeds and serves
// a port nobody is pointed at, so the client that made the change is the only
// witness that anything is wrong.
func (c *Client) SetInboundListen(l apitypes.InboundListen, guardSeconds int) (apitypes.InboundListenState, error) {
	var out apitypes.InboundListenState
	body := map[string]any{"listen": l.Listen, "port": l.Port}
	if guardSeconds > 0 {
		body["guard_seconds"] = guardSeconds
	}
	err := c.do(http.MethodPut, "/api/inbound", body, &out)
	return out, err
}

// ConfirmInboundListen cancels a pending guarded revert of the listen point.
func (c *Client) ConfirmInboundListen() error {
	return c.do(http.MethodPost, "/api/inbound/confirm", nil, nil)
}

// Retention returns how much of the daemon log and connection history stays on
// disk. Zero fields mean "no opinion" — see Defaults for what those resolve to.
func (c *Client) Retention() (apitypes.Retention, error) {
	var out apitypes.Retention
	err := c.do(http.MethodGet, "/api/retention", nil, &out)
	return out, err
}

// SetRetention replaces the retention policy, taking effect immediately (both
// halves swap a lumberjack; no rebuild).
func (c *Client) SetRetention(r apitypes.Retention) (apitypes.Retention, error) {
	var out apitypes.Retention
	err := c.do(http.MethodPut, "/api/retention", r, &out)
	return out, err
}

// Defaults returns every domain's built-in configuration.
//
// Callers render "(default 32 MB)" and "restore defaults" from this rather than
// carrying their own copy of the numbers: a second copy does not fail loudly
// when the gateway changes, it just starts describing a gateway that no longer
// exists.
func (c *Client) Defaults() (apitypes.Defaults, error) {
	var out apitypes.Defaults
	err := c.do(http.MethodGet, "/api/defaults", nil, &out)
	return out, err
}

// ProxyGroups returns the group topology config (Auto/Overseas/country/user).
func (c *Client) ProxyGroups() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/proxygroups", nil, &out)
	return out, err
}

// SetProxyGroups replaces the group topology config.
func (c *Client) SetProxyGroups(cfg any) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPut, "/api/proxygroups", cfg, &out)
	return out, err
}

// ProxyGroupsConfig returns the group topology as a typed value, for callers
// that want to patch a single field (see SetProxyGroupsConfig) rather than
// hand-assemble the whole document.
func (c *Client) ProxyGroupsConfig() (apitypes.ProxyGroupsConfig, error) {
	var out apitypes.ProxyGroupsConfig
	err := c.do(http.MethodGet, "/api/proxygroups", nil, &out)
	return out, err
}

// SetProxyGroupsConfig replaces the group topology config (typed).
func (c *Client) SetProxyGroupsConfig(cfg apitypes.ProxyGroupsConfig) (apitypes.ProxyGroupsConfig, error) {
	var out apitypes.ProxyGroupsConfig
	err := c.do(http.MethodPut, "/api/proxygroups", cfg, &out)
	return out, err
}

// ProxyScores returns the live per-member scoring view, together with the
// policy in force and the formula rendered with those weights — everything
// needed to explain a ranking without re-deriving it client-side.
func (c *Client) ProxyScores() (apitypes.ProxyScores, error) {
	var out apitypes.ProxyScores
	err := c.do(http.MethodGet, "/api/proxy-scores", nil, &out)
	return out, err
}

// ResetProxyScores discards every observation, putting all members back into
// warm-up. For "I changed provider / moved network and these numbers describe
// a different path".
func (c *Client) ResetProxyScores() error {
	return c.do(http.MethodPost, "/api/proxy-scores/reset", nil, nil)
}

// Endpoints lists WireGuard/Tailscale exits.
func (c *Client) Endpoints() ([]apitypes.Endpoint, error) {
	var out []apitypes.Endpoint
	err := c.do(http.MethodGet, "/api/endpoints", nil, &out)
	return out, err
}

// AddEndpoint registers a WireGuard/Tailscale exit.
func (c *Client) AddEndpoint(e apitypes.Endpoint) ([]apitypes.Endpoint, error) {
	var out []apitypes.Endpoint
	err := c.do(http.MethodPost, "/api/endpoints", e, &out)
	return out, err
}

// PatchEndpoint enables/disables one exit.
func (c *Client) PatchEndpoint(tag string, enabled bool) ([]apitypes.Endpoint, error) {
	var out []apitypes.Endpoint
	err := c.do(http.MethodPatch, "/api/endpoints/"+url.PathEscape(tag), map[string]bool{"enabled": enabled}, &out)
	return out, err
}

// DeleteEndpoint removes one exit.
func (c *Client) DeleteEndpoint(tag string) error {
	return c.do(http.MethodDelete, "/api/endpoints/"+url.PathEscape(tag), nil, nil)
}

// ---- proxies (via the backend's Clash proxy) ---------------------------

// Proxies returns the proxy/group tree as the console sees it.
func (c *Client) Proxies() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/proxies", nil, &out)
	return out, err
}

// SelectProxy points a selector group at one member.
func (c *Client) SelectProxy(group, name string) error {
	return c.do(http.MethodPut, "/api/proxies/select", map[string]string{"group": group, "name": name}, nil)
}

// ProxyDelay measures one proxy's latency (ms).
func (c *Client) ProxyDelay(name string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/proxies/"+url.PathEscape(name)+"/delay", nil, &out)
	return out, err
}

// ---- observability -----------------------------------------------------

// Detections returns detection events, newest first. kind/q/limit are optional.
func (c *Client) Detections(kind, q string, limit int) (map[string]any, error) {
	v := url.Values{}
	if kind != "" {
		v.Set("kind", kind)
	}
	if q != "" {
		v.Set("q", q)
	}
	if limit > 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	var out map[string]any
	err := c.do(http.MethodGet, "/api/detections?"+v.Encode(), nil, &out)
	return out, err
}

// DetectionStats returns the aggregated detection counters.
func (c *Client) DetectionStats() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/detections/stats", nil, &out)
	return out, err
}

// History returns per-connection history, newest first.
func (c *Client) History(q string, limit int) (map[string]any, error) {
	v := url.Values{}
	if q != "" {
		v.Set("q", q)
	}
	if limit > 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	var out map[string]any
	err := c.do(http.MethodGet, "/api/history?"+v.Encode(), nil, &out)
	return out, err
}

// HistoryStats returns top talkers + the 24h trend.
func (c *Client) HistoryStats() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/api/history/stats", nil, &out)
	return out, err
}

// ---- fleet (probe registry on the brain) -------------------------------

// Nodes lists registered probes.
func (c *Client) Nodes() ([]map[string]any, error) {
	var out []map[string]any
	err := c.do(http.MethodGet, "/api/nodes", nil, &out)
	return out, err
}

// AddNode registers a probe (its /api URL + bearer token).
func (c *Client) AddNode(name, apiURL, token string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPost, "/api/nodes", map[string]string{"name": name, "url": apiURL, "token": token}, &out)
	return out, err
}

// PatchNode edits a registered gateway: enable/disable, use-as-exit plus the
// credential for it, or the local entry's mode. Only the fields set are sent.
func (c *Client) PatchNode(id string, req map[string]any) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPatch, "/api/nodes/"+url.PathEscape(id), req, &out)
	return out, err
}

// DeleteNode unregisters a probe.
func (c *Client) DeleteNode(id string) error {
	return c.do(http.MethodDelete, "/api/nodes/"+url.PathEscape(id), nil, nil)
}

// ---- self-hosted exit generation ----------------------------------------

// ProxyProtocols lists the protocols GenerateProxy can build a server for.
func (c *Client) ProxyProtocols() ([]string, error) {
	var out []string
	err := c.do(http.MethodGet, "/api/proxy-gen/protocols", nil, &out)
	return out, err
}

// GenerateProxy mints a self-hosted exit: a sing-box server config, the matching
// client node, and the commands that deploy them. Nothing is stored server-side;
// the response carries fresh secrets.
func (c *Client) GenerateProxy(req apitypes.ProxyGenRequest) (apitypes.ProxyGenResult, error) {
	var out apitypes.ProxyGenResult
	err := c.do(http.MethodPost, "/api/proxy-gen", req, &out)
	return out, err
}

// ValidListKind maps a CLI-friendly name to a list store.
func ValidListKind(name string) (listKind, error) {
	switch name {
	case "permit", "whitelist":
		return ListPermit, nil
	case "deny", "blacklist":
		return ListDeny, nil
	case "no-proxy", "noproxy", "directlist":
		return ListNoProxy, nil
	}
	return "", fmt.Errorf("unknown list %q (want permit|deny|no-proxy)", name)
}

// HistoryPage is History with the records decoded, so a caller cannot read a field
// name that does not exist. See apitypes.HistoryRecord for what that cost once.
func (c *Client) HistoryPage(q string, limit int) (apitypes.HistoryPage, error) {
	v := url.Values{}
	if q != "" {
		v.Set("q", q)
	}
	if limit > 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	var out apitypes.HistoryPage
	err := c.do(http.MethodGet, "/api/history?"+v.Encode(), nil, &out)
	return out, err
}

// APIConnections returns the live connections through the backend rather than
// straight to the Clash port.
//
// The CLI used to build a raw Clash client and look for the secret in
// "data/clash-secret" — relative, so it only worked from inside a checkout, and on a
// real install it sent no secret and got 401. The absolute path would not help
// either: the data directory is root-owned and 0700, so an unprivileged CLI cannot
// read that secret by design — it is the same reason the browser never sees it. The
// backend already proxies Clash and scopes the result to the caller, which is
// strictly better than a shared secret on disk.
//
// c.Clash remains for talking to somebody else's Clash instance, which is what
// pkg/clash is for.
func (c *Client) APIConnections() (clash.Connections, error) {
	var out clash.Connections
	err := c.do(http.MethodGet, "/api/connections", nil, &out)
	return out, err
}

// APIKillConnection closes one connection through the backend.
func (c *Client) APIKillConnection(id string) error {
	return c.do(http.MethodDelete, "/api/connections/"+url.PathEscape(id), nil, nil)
}
