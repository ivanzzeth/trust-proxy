// Package api is the trust-proxy backend's own HTTP API + console host. The
// React console (pkg served at /) talks only to this single origin; connection
// data is proxied from the standard Clash API so the browser never needs the
// Clash secret. Higher-level features (subscriptions) live under /api too.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/dnscfg"
	"github.com/ivanzzeth/trust-proxy/internal/endpoints"
	"github.com/ivanzzeth/trust-proxy/internal/gateway"
	"github.com/ivanzzeth/trust-proxy/internal/history"
	"github.com/ivanzzeth/trust-proxy/internal/inbound"
	"github.com/ivanzzeth/trust-proxy/internal/nodes"
	"github.com/ivanzzeth/trust-proxy/internal/profile"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/subscription"
	"github.com/ivanzzeth/trust-proxy/internal/tuncfg"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
	"github.com/ivanzzeth/trust-proxy/pkg/clash"
)

// Applier applies subscription nodes to the running data plane (gateway.Manager).
type Applier interface {
	Apply(nodes []apitypes.Node) error
}

// WhitelistApplier hot-reloads the egress whitelist (gateway.Manager).
type WhitelistApplier interface {
	SetWhitelist(whitelist.Rules) error
}

// BlacklistApplier hot-reloads the egress blacklist (gateway.Manager).
type BlacklistApplier interface {
	SetBlacklist(blacklist.Rules) error
}

// DirectListApplier hot-reloads the no-proxy (bypass) list (gateway.Manager).
type DirectListApplier interface {
	SetDirectList(directlist.Rules) error
}

// CustomRulesApplier hot-reloads the custom routing rules (gateway.Manager).
type CustomRulesApplier interface {
	SetCustomRules(customrules.Rules) error
}

// RulesViewer projects the effective layered policy for the explain view
// (gateway.Manager).
type RulesViewer interface {
	EffectiveRules() []apitypes.RuleView
}

// ModeController switches the gateway capture mode (gateway.Manager).
type ModeController interface {
	Mode() string
	SetMode(string) error
	SetModeGuarded(mode string, revertAfter time.Duration) (string, error)
	ConfirmMode()
	PendingRevert() (to string, secondsLeft int, ok bool)
}

// RuleSetApplier hot-reloads the imported rule sets (gateway.Manager).
type RuleSetApplier interface {
	SetRuleSets(ruleset.Sets) error
}

// ProfileApplier atomically applies a whole profile in one rebuild (gateway.Manager).
type ProfileApplier interface {
	ApplyProfile(nodes []apitypes.Node, wl whitelist.Rules, sets ruleset.Sets, mode string) error
}

// DNSApplier hot-reloads the resolver policy (gateway.Manager).
type DNSApplier interface {
	SetDNS(apitypes.DNSConfig) error
}

// InboundApplier hot-reloads the mixed-inbound auth (gateway.Manager).
type InboundApplier interface {
	SetInbound(apitypes.InboundAuth) error
}

// TUNApplier hot-reloads the tun-inbound options (gateway.Manager).
type TUNApplier interface {
	SetTUN(apitypes.TUNConfig) error
}

// EndpointsApplier hot-reloads WireGuard/Tailscale exits (gateway.Manager).
type EndpointsApplier interface {
	SetEndpoints([]apitypes.Endpoint) error
}

// Options configures the API server.
type Options struct {
	Addr        string
	Store       *subscription.Store
	Applier     Applier
	Whitelist   *whitelist.Store
	WLApplier   WhitelistApplier
	Blacklist   *blacklist.Store
	BLApplier   BlacklistApplier
	Directlist  *directlist.Store
	DLApplier   DirectListApplier
	CustomRules *customrules.Store
	CRApplier   CustomRulesApplier
	RulesView   RulesViewer
	Detect      *detect.Engine
	Mode        ModeController
	RuleSets    *ruleset.Store
	RSApplier   RuleSetApplier
	Profiles    *profile.Store
	ProfApplier ProfileApplier
	DNS         *dnscfg.Store
	DNSApplier  DNSApplier
	Inbound     *inbound.Store
	InbApplier  InboundApplier
	TUN         *tuncfg.Store
	TUNApplier  TUNApplier
	Endpoints   *endpoints.Store
	EPApplier   EndpointsApplier
	History     *history.Store
	Nodes       *nodes.Store  // brain: registry of remote gateways (reverse-proxied)
	Token       string        // if set, /api/* requires this bearer token (probe mode)
	Clash       *clash.Client // low-level Clash primitives, proxied to the browser
	ConsoleDir  string        // on-disk dashboard dir (dev); used when ConsoleFS is nil
	ConsoleFS   fs.FS         // embedded dashboard build (release); wins over ConsoleDir
}

// Server exposes /api/* and serves the console.
type Server struct {
	httpSrv     *http.Server
	store       *subscription.Store
	applier     Applier
	wl          *whitelist.Store
	wlApplier   WhitelistApplier
	bl          *blacklist.Store
	blApplier   BlacklistApplier
	dl          *directlist.Store
	dlApplier   DirectListApplier
	cr          *customrules.Store
	crApplier   CustomRulesApplier
	rulesView   RulesViewer
	detect      *detect.Engine
	mode        ModeController
	rs          *ruleset.Store
	rsApplier   RuleSetApplier
	profStore   *profile.Store
	profApplier ProfileApplier
	dns         *dnscfg.Store
	dnsApplier  DNSApplier
	inbound     *inbound.Store
	inbApplier  InboundApplier
	tun         *tuncfg.Store
	tunApplier  TUNApplier
	eps         *endpoints.Store
	epApplier   EndpointsApplier
	history     *history.Store
	nodes       *nodes.Store
	token       string
	clash       *clash.Client
	consoleDir  string
	consoleFS   fs.FS
}

// NewServer builds the API server.
func NewServer(o Options) *Server {
	s := &Server{store: o.Store, applier: o.Applier, wl: o.Whitelist, wlApplier: o.WLApplier, bl: o.Blacklist, blApplier: o.BLApplier, dl: o.Directlist, dlApplier: o.DLApplier, cr: o.CustomRules, crApplier: o.CRApplier, rulesView: o.RulesView, detect: o.Detect, mode: o.Mode, rs: o.RuleSets, rsApplier: o.RSApplier, profStore: o.Profiles, profApplier: o.ProfApplier, dns: o.DNS, dnsApplier: o.DNSApplier, inbound: o.Inbound, inbApplier: o.InbApplier, tun: o.TUN, tunApplier: o.TUNApplier, eps: o.Endpoints, epApplier: o.EPApplier, history: o.History, nodes: o.Nodes, token: o.Token, clash: o.Clash, consoleDir: o.ConsoleDir, consoleFS: o.ConsoleFS}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/mode", s.handleGetMode)
	mux.HandleFunc("POST /api/mode", s.handleSetMode)
	mux.HandleFunc("POST /api/mode/confirm", s.handleConfirmMode)
	mux.HandleFunc("POST /api/autoblock", s.handleAutoBlock)
	mux.HandleFunc("GET /api/subscriptions", s.handleListSubs)
	mux.HandleFunc("POST /api/subscriptions", s.handleAddSub)
	mux.HandleFunc("DELETE /api/subscriptions/{id}", s.handleDeleteSub)
	mux.HandleFunc("POST /api/subscriptions/{id}/refresh", s.handleRefreshSub)
	mux.HandleFunc("POST /api/subscriptions/{id}/apply", s.handleApplySub)
	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("DELETE /api/connections/{id}", s.handleKillConn)
	mux.HandleFunc("DELETE /api/connections", s.handleKillAll)
	mux.HandleFunc("GET /api/proxies", s.handleProxies)
	mux.HandleFunc("PUT /api/proxies/select", s.handleSelectProxy)
	mux.HandleFunc("GET /api/proxies/{name}/delay", s.handleProxyDelay)
	mux.HandleFunc("GET /api/rules", s.handleRules)
	mux.HandleFunc("GET /api/clash-mode", s.handleGetClashMode)
	mux.HandleFunc("PUT /api/clash-mode", s.handleSetClashMode)
	mux.HandleFunc("GET /api/logs", s.handleLogs)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/whitelist", s.handleGetWhitelist)
	mux.HandleFunc("POST /api/whitelist", s.handleAddWhitelist)
	mux.HandleFunc("DELETE /api/whitelist", s.handleDelWhitelist)
	mux.HandleFunc("GET /api/blacklist", s.handleGetBlacklist)
	mux.HandleFunc("POST /api/blacklist", s.handleAddBlacklist)
	mux.HandleFunc("DELETE /api/blacklist", s.handleDelBlacklist)
	mux.HandleFunc("GET /api/directlist", s.handleGetDirectlist)
	mux.HandleFunc("POST /api/directlist", s.handleAddDirectlist)
	mux.HandleFunc("DELETE /api/directlist", s.handleDelDirectlist)
	mux.HandleFunc("GET /api/customrules", s.handleListCustomRules)
	mux.HandleFunc("POST /api/customrules", s.handleAddCustomRule)
	mux.HandleFunc("PATCH /api/customrules/{id}", s.handlePatchCustomRule)
	mux.HandleFunc("DELETE /api/customrules/{id}", s.handleDeleteCustomRule)
	mux.HandleFunc("POST /api/customrules/{id}/move", s.handleMoveCustomRule)
	mux.HandleFunc("GET /api/customrules/packs/catalog", s.handlePackCatalog)
	mux.HandleFunc("POST /api/customrules/packs/apply", s.handleApplyPack)
	mux.HandleFunc("PATCH /api/customrules/packs/{name}", s.handlePatchPack)
	mux.HandleFunc("DELETE /api/customrules/packs/{name}", s.handleDeletePack)
	mux.HandleFunc("GET /api/effective-rules", s.handleEffectiveRules)
	mux.HandleFunc("GET /api/rulesets", s.handleListRuleSets)
	mux.HandleFunc("GET /api/rulesets/catalog", s.handleRuleSetCatalog)
	mux.HandleFunc("GET /api/rulesets/{tag}/rules", s.handleRuleSetRules)
	mux.HandleFunc("POST /api/rulesets", s.handleAddRuleSet)
	mux.HandleFunc("PATCH /api/rulesets/{tag}", s.handlePatchRuleSet)
	mux.HandleFunc("DELETE /api/rulesets/{tag}", s.handleDeleteRuleSet)
	mux.HandleFunc("GET /api/history/stats", s.handleHistoryStats)
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("GET /api/nodes", s.handleListNodes)
	mux.HandleFunc("POST /api/nodes", s.handleAddNode)
	mux.HandleFunc("DELETE /api/nodes/{id}", s.handleDeleteNode)
	mux.HandleFunc("/api/nodes/{id}/{rest...}", s.handleNodeProxy) // reverse proxy to a probe
	mux.HandleFunc("GET /api/dns", s.handleGetDNS)
	mux.HandleFunc("PUT /api/dns", s.handleSetDNS)
	mux.HandleFunc("GET /api/inbound", s.handleGetInbound)
	mux.HandleFunc("PUT /api/inbound", s.handleSetInbound)
	mux.HandleFunc("GET /api/tun", s.handleGetTUN)
	mux.HandleFunc("GET /api/endpoints", s.handleListEndpoints)
	mux.HandleFunc("POST /api/endpoints", s.handleAddEndpoint)
	mux.HandleFunc("PATCH /api/endpoints/{tag}", s.handlePatchEndpoint)
	mux.HandleFunc("DELETE /api/endpoints/{tag}", s.handleDeleteEndpoint)
	mux.HandleFunc("PUT /api/tun", s.handleSetTUN)
	mux.HandleFunc("GET /api/profiles", s.handleListProfiles)
	mux.HandleFunc("POST /api/profiles", s.handleAddProfile)
	mux.HandleFunc("POST /api/profiles/{id}/activate", s.handleActivateProfile)
	mux.HandleFunc("DELETE /api/profiles/{id}", s.handleDeleteProfile)
	mux.Handle("/", s.consoleHandler())
	s.httpSrv = &http.Server{Addr: o.Addr, Handler: s.withAuth(mux), ReadHeaderTimeout: 5 * time.Second}
	return s
}

// withAuth requires a bearer token on /api/* when a token is configured (probe
// mode). Static console assets stay open so the page can load.
func (s *Server) withAuth(next http.Handler) http.Handler {
	if s.token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
				writeErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Start blocks serving; returns http.ErrServerClosed on Close.
func (s *Server) Start() error { return s.httpSrv.ListenAndServe() }

// Close shuts the server down.
func (s *Server) Close() error { return s.httpSrv.Close() }

// ---- subscriptions --------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- status / mode / auto-block -------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := map[string]any{
		"modes": gateway.Modes,
		"root":  os.Geteuid() == 0,
	}
	if s.mode != nil {
		st["mode"] = s.mode.Mode()
		if to, left, ok := s.mode.PendingRevert(); ok {
			st["revert"] = map[string]any{"to": to, "in_seconds": left}
		}
	}
	if s.detect != nil {
		d, ip := s.detect.ThreatCounts()
		st["autoBlock"] = s.detect.AutoBlock()
		st["threats"] = map[string]int{"domains": d, "ips": ip}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleGetMode(w http.ResponseWriter, r *http.Request) {
	if s.mode == nil {
		writeErr(w, http.StatusServiceUnavailable, "mode controller not available")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": s.mode.Mode(), "modes": gateway.Modes})
}

func (s *Server) handleSetMode(w http.ResponseWriter, r *http.Request) {
	if s.mode == nil {
		writeErr(w, http.StatusServiceUnavailable, "mode controller not available")
		return
	}
	var req struct {
		Mode         string `json:"mode"`
		GuardSeconds int    `json:"guard_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Mode == "" {
		writeErr(w, http.StatusBadRequest, "mode is required")
		return
	}
	resp := map[string]any{}
	if req.GuardSeconds > 0 {
		to, err := s.mode.SetModeGuarded(req.Mode, time.Duration(req.GuardSeconds)*time.Second)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if to != "" && to != req.Mode {
			resp["revert"] = map[string]any{"to": to, "in_seconds": req.GuardSeconds}
		}
	} else if err := s.mode.SetMode(req.Mode); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	resp["mode"] = s.mode.Mode()
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleConfirmMode(w http.ResponseWriter, r *http.Request) {
	if s.mode == nil {
		writeErr(w, http.StatusServiceUnavailable, "mode controller not available")
		return
	}
	s.mode.ConfirmMode()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAutoBlock(w http.ResponseWriter, r *http.Request) {
	if s.detect == nil {
		writeErr(w, http.StatusServiceUnavailable, "detection not available")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "enabled is required")
		return
	}
	s.detect.SetAutoBlock(req.Enabled)
	writeJSON(w, http.StatusOK, map[string]any{"autoBlock": req.Enabled})
}

func (s *Server) handleListSubs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.List())
}

func (s *Server) handleAddSub(w http.ResponseWriter, r *http.Request) {
	var req apitypes.AddSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.URL == "" && req.Content == "" {
		writeErr(w, http.StatusBadRequest, "url or content is required")
		return
	}
	sub, err := s.store.Add(req.Name, req.URL, req.UserAgent, req.Via, req.Content)
	if err != nil {
		log.Println("subscription add refresh:", err)
	}
	writeJSON(w, http.StatusCreated, sub)
}

func (s *Server) handleDeleteSub(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRefreshSub(w http.ResponseWriter, r *http.Request) {
	sub, err := s.store.Refresh(r.PathValue("id"))
	if err != nil {
		if _, ok := s.store.Get(r.PathValue("id")); !ok {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		log.Println("subscription refresh:", err)
	}
	writeJSON(w, http.StatusOK, sub)
}

func (s *Server) handleApplySub(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "subscription not found")
		return
	}
	if s.applier == nil {
		writeErr(w, http.StatusServiceUnavailable, "gateway applier not available")
		return
	}
	if err := s.applier.Apply(sub.Nodes); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetApplied(sub.ID); err != nil {
		log.Println("mark applied:", err)
	}
	sub, _ = s.store.Get(sub.ID)
	writeJSON(w, http.StatusOK, sub)
}

// ---- connections (proxied from the Clash API) -----------------------------

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	snap, err := s.clash.Connections()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handleKillConn(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	if err := s.clash.CloseConnection(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleKillAll(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	if err := s.clash.CloseAllConnections(); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- console static host --------------------------------------------------

// consoleHandler serves the dashboard from an fs.FS — either the embedded build
// (go:embed, release binaries) or the on-disk dir (dev). SPA fallback to
// index.html; a short hint if the build is missing.
func (s *Server) consoleHandler() http.Handler {
	fsys := s.consoleFS // embedded build (release) if set...
	if fsys == nil {
		fsys = os.DirFS(s.consoleDir) // ...else on-disk (dev)
	}
	fileSrv := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fs.Stat(fsys, "index.html"); err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("trust-proxy dashboard not built.\nRun: make dashboard (or build with -tags embed_ui)\n"))
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" && p != "." {
			if st, err := fs.Stat(fsys, p); err == nil && !st.IsDir() {
				fileSrv.ServeHTTP(w, r)
				return
			}
		}
		http.ServeFileFS(w, r, fsys, "index.html") // SPA fallback
	})
}

// ---- detection events ------------------------------------------------------

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.detect == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	events := s.detect.Events()
	if r.URL.Query().Get("level") == "alert" {
		filtered := events[:0:0]
		for _, e := range events {
			if e.Level == "alert" {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}
	writeJSON(w, http.StatusOK, events)
}

// ---- whitelist (egress allow-list) ----------------------------------------

type whitelistReq struct {
	Type  string `json:"type"` // "domain" | "ip"
	Value string `json:"value"`
}

func (s *Server) handleGetWhitelist(w http.ResponseWriter, r *http.Request) {
	if s.wl == nil {
		writeErr(w, http.StatusServiceUnavailable, "whitelist not available")
		return
	}
	writeJSON(w, http.StatusOK, s.wl.Get())
}

func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	s.mutateWhitelist(w, r, true)
}

func (s *Server) handleDelWhitelist(w http.ResponseWriter, r *http.Request) {
	s.mutateWhitelist(w, r, false)
}

func (s *Server) mutateWhitelist(w http.ResponseWriter, r *http.Request, add bool) {
	if s.wl == nil {
		writeErr(w, http.StatusServiceUnavailable, "whitelist not available")
		return
	}
	var req whitelistReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Value == "" {
		writeErr(w, http.StatusBadRequest, "type and value are required")
		return
	}
	prev := s.wl.Get() // for rollback if the apply fails
	var (
		rules whitelist.Rules
		err   error
	)
	switch req.Type {
	case "domain":
		if add {
			rules, err = s.wl.AddDomain(req.Value)
		} else {
			rules, err = s.wl.RemoveDomain(req.Value)
		}
	case "ip":
		if add {
			rules, err = s.wl.AddIP(req.Value)
		} else {
			rules, err = s.wl.RemoveIP(req.Value)
		}
	case "process":
		if add {
			rules, err = s.wl.AddProcess(req.Value)
		} else {
			rules, err = s.wl.RemoveProcess(req.Value)
		}
	case "device":
		if add {
			rules, err = s.wl.AddDevice(req.Value)
		} else {
			rules, err = s.wl.RemoveDevice(req.Value)
		}
	default:
		writeErr(w, http.StatusBadRequest, "type must be domain, ip, process or device")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error()) // validation error (bad IP/domain)
		return
	}
	if s.wlApplier != nil {
		if err := s.wlApplier.SetWhitelist(rules); err != nil {
			_, _ = s.wl.Set(prev) // un-poison the store so it matches the running plane
			writeErr(w, http.StatusBadGateway, "apply whitelist: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, rules)
}

// ---- blacklist (egress deny-list) -----------------------------------------

type blacklistReq struct {
	Type  string `json:"type"` // "domain" | "keyword" | "regex" | "ip"
	Value string `json:"value"`
}

func (s *Server) handleGetBlacklist(w http.ResponseWriter, r *http.Request) {
	if s.bl == nil {
		writeErr(w, http.StatusServiceUnavailable, "blacklist not available")
		return
	}
	writeJSON(w, http.StatusOK, s.bl.Get())
}

func (s *Server) handleAddBlacklist(w http.ResponseWriter, r *http.Request) {
	s.mutateBlacklist(w, r, true)
}

func (s *Server) handleDelBlacklist(w http.ResponseWriter, r *http.Request) {
	s.mutateBlacklist(w, r, false)
}

func (s *Server) mutateBlacklist(w http.ResponseWriter, r *http.Request, add bool) {
	if s.bl == nil {
		writeErr(w, http.StatusServiceUnavailable, "blacklist not available")
		return
	}
	var req blacklistReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Value == "" {
		writeErr(w, http.StatusBadRequest, "type and value are required")
		return
	}
	prev := s.bl.Get() // for rollback if the apply fails
	var (
		rules blacklist.Rules
		err   error
	)
	switch req.Type {
	case "domain":
		if add {
			rules, err = s.bl.AddDomain(req.Value)
		} else {
			rules, err = s.bl.RemoveDomain(req.Value)
		}
	case "keyword":
		if add {
			rules, err = s.bl.AddKeyword(req.Value)
		} else {
			rules, err = s.bl.RemoveKeyword(req.Value)
		}
	case "regex":
		if add {
			rules, err = s.bl.AddRegex(req.Value)
		} else {
			rules, err = s.bl.RemoveRegex(req.Value)
		}
	case "ip":
		if add {
			rules, err = s.bl.AddIP(req.Value)
		} else {
			rules, err = s.bl.RemoveIP(req.Value)
		}
	default:
		writeErr(w, http.StatusBadRequest, "type must be domain, keyword, regex or ip")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error()) // validation error (bad IP/regex)
		return
	}
	if s.blApplier != nil {
		if err := s.blApplier.SetBlacklist(rules); err != nil {
			_, _ = s.bl.Set(prev) // un-poison the store so it matches the running plane
			writeErr(w, http.StatusBadGateway, "apply blacklist: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, rules)
}

// ---- directlist (no-proxy / bypass, routing layer) ------------------------

type directlistReq struct {
	Type  string `json:"type"` // "domain" | "ip"
	Value string `json:"value"`
}

func (s *Server) handleGetDirectlist(w http.ResponseWriter, r *http.Request) {
	if s.dl == nil {
		writeErr(w, http.StatusServiceUnavailable, "directlist not available")
		return
	}
	writeJSON(w, http.StatusOK, s.dl.Get())
}

func (s *Server) handleAddDirectlist(w http.ResponseWriter, r *http.Request) {
	s.mutateDirectlist(w, r, true)
}

func (s *Server) handleDelDirectlist(w http.ResponseWriter, r *http.Request) {
	s.mutateDirectlist(w, r, false)
}

func (s *Server) mutateDirectlist(w http.ResponseWriter, r *http.Request, add bool) {
	if s.dl == nil {
		writeErr(w, http.StatusServiceUnavailable, "directlist not available")
		return
	}
	var req directlistReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Value == "" {
		writeErr(w, http.StatusBadRequest, "type and value are required")
		return
	}
	prev := s.dl.Get() // for rollback if the apply fails
	var (
		rules directlist.Rules
		err   error
	)
	switch req.Type {
	case "domain":
		if add {
			rules, err = s.dl.AddDomain(req.Value)
		} else {
			rules, err = s.dl.RemoveDomain(req.Value)
		}
	case "ip":
		if add {
			rules, err = s.dl.AddIP(req.Value)
		} else {
			rules, err = s.dl.RemoveIP(req.Value)
		}
	default:
		writeErr(w, http.StatusBadRequest, "type must be domain or ip")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error()) // validation error (bad IP)
		return
	}
	if s.dlApplier != nil {
		if err := s.dlApplier.SetDirectList(rules); err != nil {
			_, _ = s.dl.Set(prev) // un-poison the store so it matches the running plane
			writeErr(w, http.StatusBadGateway, "apply directlist: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, rules)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, apitypes.ErrorResponse{Error: msg})
}
