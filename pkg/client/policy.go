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

// listEntry is the shared {type,value} mutation body.
type listEntry struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// AddListEntry adds one entry. typ is domain|ip|process|device (per list).
func (c *Client) AddListEntry(kind listKind, typ, value string) (apitypes.ACLList, error) {
	var out apitypes.ACLList
	err := c.do(http.MethodPost, "/api/"+string(kind), listEntry{Type: typ, Value: value}, &out)
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

// Inbound returns the mixed inbound's auth settings.
func (c *Client) Inbound() (apitypes.InboundAuth, error) {
	var out apitypes.InboundAuth
	err := c.do(http.MethodGet, "/api/inbound", nil, &out)
	return out, err
}

// SetInbound sets (or clears, with both empty) inbound auth.
func (c *Client) SetInbound(a apitypes.InboundAuth) (apitypes.InboundAuth, error) {
	var out apitypes.InboundAuth
	err := c.do(http.MethodPut, "/api/inbound", a, &out)
	return out, err
}

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

// DeleteNode unregisters a probe.
func (c *Client) DeleteNode(id string) error {
	return c.do(http.MethodDelete, "/api/nodes/"+url.PathEscape(id), nil, nil)
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
