// Package api is the trust-proxy backend's own HTTP API + console host. The
// React console (pkg served at /) talks only to this single origin; connection
// data is proxied from the standard Clash API so the browser never needs the
// Clash secret. Higher-level features (subscriptions) live under /api too.
package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/authn"
	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/detectcfg"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/dnscfg"
	"github.com/ivanzzeth/trust-proxy/internal/doctor"
	"github.com/ivanzzeth/trust-proxy/internal/endpoints"
	"github.com/ivanzzeth/trust-proxy/internal/finalroute"
	"github.com/ivanzzeth/trust-proxy/internal/gateway"
	"github.com/ivanzzeth/trust-proxy/internal/history"
	"github.com/ivanzzeth/trust-proxy/internal/inboundcfg"
	"github.com/ivanzzeth/trust-proxy/internal/logging"
	"github.com/ivanzzeth/trust-proxy/internal/nodes"
	"github.com/ivanzzeth/trust-proxy/internal/paths"
	"github.com/ivanzzeth/trust-proxy/internal/posture"
	"github.com/ivanzzeth/trust-proxy/internal/profile"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/internal/retentioncfg"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/subscription"
	"github.com/ivanzzeth/trust-proxy/internal/tuncfg"
	"github.com/ivanzzeth/trust-proxy/internal/users"
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

// ProxyGroupsApplier hot-reloads the proxy-group config (gateway.Manager).
type ProxyGroupsApplier interface {
	SetProxyGroups(proxygroups.Config) error
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
	ApplyProfile(
		nodes []apitypes.Node,
		wl whitelist.Rules,
		bl blacklist.Rules,
		dl directlist.Rules,
		cr customrules.Rules,
		sets ruleset.Sets,
		pg proxygroups.Config,
		dns apitypes.DNSConfig,
		mode string,
		final string,
		posture string, // empty = keep current Strict|Split posture
	) error
	Nodes() []apitypes.Node
	Posture() string
	SetPosture(string) error
}

// FinalApplier hot-reloads the catch-all Final egress (gateway.Manager).
type FinalApplier interface {
	Final() string
	SetFinal(string) error
}

// DNSApplier hot-reloads the resolver policy (gateway.Manager).
type DNSApplier interface {
	SetDNS(apitypes.DNSConfig) error
}

// InboundApplier hot-reloads the proxy inbound's credential list
// (gateway.Manager). The list is derived from the user registry — there is no
// separate inbound-auth store: one list of people, each of whom may or may not
// have a proxy password.
type InboundApplier interface {
	SetInbound(apitypes.InboundAuth) error
}

// InboundListenApplier moves the proxy inbound's listen point (gateway.Manager).
//
// Separate from InboundApplier because the two have opposite risk profiles: a
// credential change cannot make the gateway unreachable, and moving the port
// disconnects every client at once. Hence the guard, which is its own rather
// than ModeController's — the mode and the listen point can be mid-change
// independently, and one shared timer would let confirming either cancel the
// other's rollback.
type InboundListenApplier interface {
	InboundListen() apitypes.InboundListen
	SetInboundListen(apitypes.InboundListen) error
	SetInboundListenGuarded(l apitypes.InboundListen, revertAfter time.Duration) (apitypes.InboundListen, error)
	ConfirmInboundListen()
	PendingInboundRevert() (to apitypes.InboundListen, secondsLeft int, ok bool)
}

// RetentionApplier swaps the live log/history rotation policy. Unlike the other
// appliers here it does not rebuild the box: both halves just replace a
// lumberjack behind a mutex.
type RetentionApplier interface {
	SetRetention(apitypes.Retention) error
}

// TUNApplier hot-reloads the tun-inbound options (gateway.Manager).
type TUNApplier interface {
	SetTUN(apitypes.TUNConfig) error
}

// GatewayExitApplier hot-reloads the gateways used as egress (gateway.Manager).
type GatewayExitApplier interface {
	SetGatewayExits([]apitypes.Node) error
}

// ClientModeApplier switches between enforcing policy and deferring to a gateway.
type ClientModeApplier interface {
	SetClientMode(bool) error
}

// EndpointsApplier hot-reloads WireGuard/Tailscale exits (gateway.Manager).
type EndpointsApplier interface {
	SetEndpoints([]apitypes.Endpoint) error
}

// Options configures the API server.
type Options struct {
	Addr         string
	Store        *subscription.Store
	Applier      Applier
	Whitelist    *whitelist.Store
	WLApplier    WhitelistApplier
	Blacklist    *blacklist.Store
	BLApplier    BlacklistApplier
	Directlist   *directlist.Store
	DLApplier    DirectListApplier
	QueryStats   QueryStatsProvider
	NetState     NetworkStateProvider
	Fingerprints FingerprintProvider
	Detection    *detectcfg.Store
	DetApplier   DetectionApplier
	Quarantine   *quarantine.Store
	QuarApplier  QuarantineApplier
	CustomRules  *customrules.Store
	CRApplier    CustomRulesApplier
	RulesView    RulesViewer
	ProxyGroups  *proxygroups.Store
	PGApplier    ProxyGroupsApplier
	Scorer       ProxyScorer
	Detect       *detect.Engine
	Mode         ModeController
	RuleSets     *ruleset.Store
	RSApplier    RuleSetApplier
	Profiles     *profile.Store
	ProfApplier  ProfileApplier
	Posture      *posture.Store
	Final        *finalroute.Store
	FinalApplier FinalApplier
	DNS          *dnscfg.Store
	DNSApplier   DNSApplier
	Users        *users.Store // console accounts, roles, API keys
	Authn        *authn.Authn // session tokens (JWT); nil disables sessions
	DataDir      string       // where the bootstrap code and other secrets live
	InbApplier   InboundApplier
	InbListen    *inboundcfg.Store
	InbListenApp InboundListenApplier
	Retention    *retentioncfg.Store
	RetApplier   RetentionApplier
	TUN          *tuncfg.Store
	TUNApplier   TUNApplier
	Endpoints    *endpoints.Store
	EPApplier    EndpointsApplier
	History      *history.Store
	Detections   *detect.Store // durable alert findings (JSONL)
	Nodes        *nodes.Store  // brain: registry of remote gateways (reverse-proxied)
	GWApplier    GatewayExitApplier
	CMApplier    ClientModeApplier
	Token        string        // if set, /api/* requires this bearer token (probe mode)
	Version      string        // this build's version, reported on /api/health from loopback
	Clash        *clash.Client // low-level Clash primitives, proxied to the browser
	ConsoleDir   string        // on-disk dashboard dir (dev); used when ConsoleFS is nil
	ConsoleFS    fs.FS         // embedded dashboard build (release); wins over ConsoleDir
}

// Server exposes /api/* and serves the console.
type Server struct {
	httpSrv      *http.Server
	store        *subscription.Store
	applier      Applier
	wl           *whitelist.Store
	wlApplier    WhitelistApplier
	bl           *blacklist.Store
	blApplier    BlacklistApplier
	queryStats   QueryStatsProvider
	netstate     NetworkStateProvider
	fingerprints FingerprintProvider
	detcfg       *detectcfg.Store
	detApplier   DetectionApplier
	quar         *quarantine.Store
	quarApplier  QuarantineApplier
	dl           *directlist.Store
	dlApplier    DirectListApplier
	cr           *customrules.Store
	crApplier    CustomRulesApplier
	rulesView    RulesViewer
	pgroups      *proxygroups.Store
	pgApplier    ProxyGroupsApplier
	scorer       ProxyScorer
	detect       *detect.Engine
	mode         ModeController
	rs           *ruleset.Store
	rsApplier    RuleSetApplier
	profStore    *profile.Store
	profApplier  ProfileApplier
	posture      *posture.Store
	final        *finalroute.Store
	finalApplier FinalApplier
	dns          *dnscfg.Store
	dnsApplier   DNSApplier
	users        *users.Store
	authn        *authn.Authn
	dataDir      string
	inbApplier   InboundApplier
	// inbListen is where the proxy listens; inbListenApplier moves it. Kept apart
	// from inbApplier: see InboundListenApplier.
	inbListen        *inboundcfg.Store
	inbListenApplier InboundListenApplier
	retention        *retentioncfg.Store
	retApplier       RetentionApplier
	tun              *tuncfg.Store
	tunApplier       TUNApplier
	eps              *endpoints.Store
	epApplier        EndpointsApplier
	history          *history.Store
	detections       *detect.Store
	nodes            *nodes.Store
	gwApplier        GatewayExitApplier
	cmApplier        ClientModeApplier
	token            string
	clash            *clash.Client
	consoleDir       string
	consoleFS        fs.FS
	// version and managedBinary describe *this build*, so /api/health can tell a
	// caller which gateway it actually reached (see handleHealth).
	version       string
	managedBinary bool
	// throttle bounds the public endpoints that do real work for an
	// unauthenticated caller; nil disables it (tests that do not care).
	throttle *throttle
	// reach answers "can this machine fetch from these hosts", for rule-set source
	// selection. A field so a test can drive the posture handler without asking the
	// question of the actual internet — otherwise the test measures GitHub's
	// availability rather than the code, and the bug it exists for (a seeded slot
	// never being re-resolved) lives in the handler rather than in the resolver.
	reach func(probe map[string]string) map[string]bool
}

// NewServer builds the API server.
func NewServer(o Options) *Server {
	s := &Server{queryStats: o.QueryStats, netstate: o.NetState, fingerprints: o.Fingerprints, detcfg: o.Detection, detApplier: o.DetApplier, quar: o.Quarantine, quarApplier: o.QuarApplier, store: o.Store, applier: o.Applier, wl: o.Whitelist, wlApplier: o.WLApplier, bl: o.Blacklist, blApplier: o.BLApplier, dl: o.Directlist, dlApplier: o.DLApplier, cr: o.CustomRules, crApplier: o.CRApplier, rulesView: o.RulesView, pgroups: o.ProxyGroups, pgApplier: o.PGApplier, scorer: o.Scorer, detect: o.Detect, mode: o.Mode, rs: o.RuleSets, rsApplier: o.RSApplier, profStore: o.Profiles, profApplier: o.ProfApplier, posture: o.Posture, final: o.Final, finalApplier: o.FinalApplier, dns: o.DNS, dnsApplier: o.DNSApplier, users: o.Users, authn: o.Authn, dataDir: o.DataDir, inbApplier: o.InbApplier, inbListen: o.InbListen, inbListenApplier: o.InbListenApp, retention: o.Retention, retApplier: o.RetApplier, tun: o.TUN, tunApplier: o.TUNApplier, eps: o.Endpoints, epApplier: o.EPApplier, history: o.History, detections: o.Detections, nodes: o.Nodes, gwApplier: o.GWApplier, cmApplier: o.CMApplier, token: o.Token, clash: o.Clash, consoleDir: o.ConsoleDir, consoleFS: o.ConsoleFS,
		version: o.Version, managedBinary: runningTheManagedCopy(),
		throttle: newThrottle(defaultLoginConcurrency, defaultLoginAttempts, defaultLoginWindow)}
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	mux.Handle("/", s.consoleHandler())
	s.httpSrv = &http.Server{Addr: o.Addr, Handler: s.withAuth(mux), ReadHeaderTimeout: 5 * time.Second}
	return s
}

// registerRoutes binds every /api handler.
//
// A method rather than inline in NewServer so the drift test can collect the
// pattern set from a bare Server: taking a method value does not call it, and the
// test only needs the patterns. Before this, the set of served routes was only
// observable after a fully wired server happened to be constructed, which made the
// test that keeps routeLevels honest depend on the order tests ran in.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	s.route(mux, "GET /api/health", s.handleHealth)
	s.route(mux, "GET /api/status", s.handleStatus)
	s.route(mux, "POST /api/doctor/nftables/install", s.handleInstallNftables)
	s.route(mux, "GET /api/mode", s.handleGetMode)
	s.route(mux, "POST /api/mode", s.handleSetMode)
	s.route(mux, "GET /api/posture", s.handleGetPosture)
	s.route(mux, "PUT /api/posture", s.handleSetPosture)
	s.route(mux, "POST /api/mode/confirm", s.handleConfirmMode)
	s.route(mux, "POST /api/autoblock", s.handleAutoBlock)
	s.route(mux, "GET /api/subscriptions", s.handleListSubs)
	s.route(mux, "POST /api/subscriptions", s.handleAddSub)
	s.route(mux, "GET /api/proxy-gen/protocols", s.handleProxyProtocols)
	s.route(mux, "POST /api/proxy-gen", s.handleProxyGen)
	s.route(mux, "DELETE /api/subscriptions/{id}", s.handleDeleteSub)
	s.route(mux, "GET /api/subscriptions/{id}/export", s.handleExportSub)
	s.route(mux, "POST /api/subscriptions/{id}/refresh", s.handleRefreshSub)
	s.route(mux, "POST /api/subscriptions/{id}/apply", s.handleApplySub)
	s.route(mux, "POST /api/subscriptions/{id}/unapply", s.handleUnapplySub)
	s.route(mux, "GET /api/connections", s.handleConnections)
	s.route(mux, "DELETE /api/connections/{id}", s.handleKillConn)
	s.route(mux, "DELETE /api/connections", s.handleKillAll)
	s.route(mux, "GET /api/proxies", s.handleProxies)
	s.route(mux, "PUT /api/proxies/select", s.handleSelectProxy)
	s.route(mux, "GET /api/proxies/{name}/delay", s.handleProxyDelay)
	s.route(mux, "GET /api/rules", s.handleRules)
	s.route(mux, "GET /api/clash-mode", s.handleGetClashMode)
	s.route(mux, "PUT /api/clash-mode", s.handleSetClashMode)
	s.route(mux, "GET /api/logs", s.handleLogs)
	s.route(mux, "GET /api/traffic", s.handleTraffic)
	s.route(mux, "GET /api/events", s.handleEvents)
	s.route(mux, "GET /api/dns-queries/stats", s.handleDNSQueryStats)
	s.route(mux, "GET /api/netcheck", s.handleNetcheck)
	s.route(mux, "GET /api/fingerprints", s.handleFingerprints)
	s.route(mux, "GET /api/detection-config", s.handleGetDetectionConfig)
	s.route(mux, "PUT /api/detection-config", s.handleSetDetectionConfig)
	s.route(mux, "GET /api/quarantine", s.handleListQuarantine)
	s.route(mux, "DELETE /api/quarantine", s.handleReleaseQuarantine)
	s.route(mux, "POST /api/quarantine/permit", s.handlePermitQuarantine)
	s.route(mux, "GET /api/detections", s.handleDetections)
	s.route(mux, "GET /api/detections/stats", s.handleDetectionsStats)
	s.route(mux, "GET /api/whitelist", s.handleGetWhitelist)
	s.route(mux, "POST /api/whitelist", s.handleAddWhitelist)
	s.route(mux, "DELETE /api/whitelist", s.handleDelWhitelist)
	s.route(mux, "GET /api/blacklist", s.handleGetBlacklist)
	s.route(mux, "POST /api/blacklist", s.handleAddBlacklist)
	s.route(mux, "DELETE /api/blacklist", s.handleDelBlacklist)
	s.route(mux, "GET /api/directlist", s.handleGetDirectlist)
	s.route(mux, "POST /api/directlist", s.handleAddDirectlist)
	s.route(mux, "DELETE /api/directlist", s.handleDelDirectlist)
	s.route(mux, "GET /api/customrules", s.handleListCustomRules)
	s.route(mux, "POST /api/customrules", s.handleAddCustomRule)
	s.route(mux, "PATCH /api/customrules/{id}", s.handlePatchCustomRule)
	s.route(mux, "DELETE /api/customrules/{id}", s.handleDeleteCustomRule)
	s.route(mux, "POST /api/customrules/{id}/move", s.handleMoveCustomRule)
	s.route(mux, "GET /api/customrules/packs/catalog", s.handlePackCatalog)
	s.route(mux, "POST /api/customrules/packs/apply", s.handleApplyPack)
	s.route(mux, "PATCH /api/customrules/packs/{name}", s.handlePatchPack)
	s.route(mux, "DELETE /api/customrules/packs/{name}", s.handleDeletePack)
	// Permit requests: a client may ask, an admin approves. See requests.go.
	s.route(mux, "POST /api/permit-requests", s.handleCreatePermitRequest)
	s.route(mux, "GET /api/permit-requests", s.handleListPermitRequests)
	s.route(mux, "POST /api/permit-requests/{id}/approve", s.handleApprovePermitRequest)
	s.route(mux, "DELETE /api/permit-requests/{id}", s.handleDenyPermitRequest)
	s.route(mux, "GET /api/effective-rules", s.handleEffectiveRules)
	s.route(mux, "GET /api/proxygroups", s.handleGetProxyGroups)
	s.route(mux, "PUT /api/proxygroups", s.handleSetProxyGroups)
	s.route(mux, "GET /api/proxy-scores", s.handleGetProxyScores)
	s.route(mux, "POST /api/proxy-scores/reset", s.handleResetProxyScores)
	s.route(mux, "GET /api/rulesets", s.handleListRuleSets)
	s.route(mux, "GET /api/rulesets/catalog", s.handleRuleSetCatalog)
	s.route(mux, "GET /api/rulesets/{tag}/rules", s.handleRuleSetRules)
	s.route(mux, "POST /api/rulesets", s.handleAddRuleSet)
	s.route(mux, "PATCH /api/rulesets/{tag}", s.handlePatchRuleSet)
	s.route(mux, "DELETE /api/rulesets/{tag}", s.handleDeleteRuleSet)
	s.route(mux, "GET /api/history/stats", s.handleHistoryStats)
	s.route(mux, "GET /api/history", s.handleHistory)
	s.route(mux, "GET /api/nodes", s.handleListNodes)
	s.route(mux, "POST /api/nodes", s.handleAddNode)
	s.route(mux, "PATCH /api/nodes/{id}", s.handlePatchNode)
	s.route(mux, "DELETE /api/nodes/{id}", s.handleDeleteNode)
	s.route(mux, "/api/nodes/{id}/{rest...}", s.handleNodeProxy) // reverse proxy to a probe
	s.route(mux, "GET /api/dns", s.handleGetDNS)
	s.route(mux, "PUT /api/dns", s.handleSetDNS)
	s.route(mux, "GET /api/final", s.handleGetFinal)
	s.route(mux, "PUT /api/final", s.handleSetFinal)
	s.route(mux, "GET /api/tun", s.handleGetTUN)
	s.route(mux, "GET /api/endpoints", s.handleListEndpoints)
	s.route(mux, "POST /api/endpoints", s.handleAddEndpoint)
	s.route(mux, "PATCH /api/endpoints/{tag}", s.handlePatchEndpoint)
	s.route(mux, "DELETE /api/endpoints/{tag}", s.handleDeleteEndpoint)
	s.route(mux, "PUT /api/tun", s.handleSetTUN)
	s.route(mux, "GET /api/inbound", s.handleGetInbound)
	s.route(mux, "PUT /api/inbound", s.handleSetInbound)
	s.route(mux, "POST /api/inbound/confirm", s.handleConfirmInbound)
	s.route(mux, "GET /api/retention", s.handleGetRetention)
	s.route(mux, "PUT /api/retention", s.handleSetRetention)
	s.route(mux, "GET /api/defaults", s.handleDefaults)
	s.route(mux, "GET /api/profiles", s.handleListProfiles)
	s.route(mux, "POST /api/profiles", s.handleAddProfile)
	s.route(mux, "POST /api/profiles/{id}/activate", s.handleActivateProfile)
	s.route(mux, "DELETE /api/profiles/{id}", s.handleDeleteProfile)
	// auth + user administration
	s.route(mux, "GET /api/auth/state", s.handleAuthState)
	s.route(mux, "GET /api/auth/me", s.handleAuthMe)
	s.route(mux, "POST /api/auth/bootstrap", s.handleBootstrap)
	s.route(mux, "POST /api/auth/login", s.handleLogin)
	s.route(mux, "POST /api/auth/logout", s.handleLogout)
	// Asymmetric on purpose: POST needs a credential and hands out a ticket, GET
	// needs none and spends one (see requirement()).
	s.route(mux, "POST /api/auth/ticket", s.handleMintTicket)
	s.route(mux, "GET /api/auth/ticket", s.handleRedeemTicket)
	s.route(mux, "POST /api/auth/register", s.handleRegister)
	s.route(mux, "GET /api/auth/settings", s.handleGetAuthSettings)
	s.route(mux, "PUT /api/auth/settings", s.handleSetAuthSettings)
	s.route(mux, "GET /api/users", s.handleListUsers)
	s.route(mux, "POST /api/users", s.handleCreateUser)
	s.route(mux, "PATCH /api/users/{id}", s.handlePatchUser)
	s.route(mux, "DELETE /api/users/{id}", s.handleDeleteUser)
	s.route(mux, "POST /api/users/{id}/apikeys", s.handleCreateAPIKey)
	s.route(mux, "DELETE /api/users/{id}/apikeys/{keyID}", s.handleDeleteAPIKey)
}

// runningTheManagedCopy reports whether this process is the binary `install`
// put at the fixed managed path — i.e. whether it is the system gateway rather
// than a `serve` somebody started by hand.
//
// Resolving symlinks on both sides: the managed path is a real file, but the
// process may have been reached through one, and a mismatch here would tell the
// desktop app to offer taking over the very service it is talking to.
func runningTheManagedCopy() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	managed := paths.ManagedBinary()
	if resolved, err := filepath.EvalSymlinks(managed); err == nil {
		managed = resolved
	}
	return exe == managed
}

// Start blocks serving; returns http.ErrServerClosed on Close.
func (s *Server) Start() error { return s.httpSrv.ListenAndServe() }

// Close shuts the server down.
func (s *Server) Close() error { return s.httpSrv.Close() }

// ---- subscriptions --------------------------------------------------------

// handleHealth is the liveness probe, and the one place a caller can learn which
// *build* is actually running here.
//
// The version matters because nothing else could see it: a desktop app opened
// after an upgrade probes this, finds a healthy gateway, attaches — and shows the
// old daemon's console with nothing anywhere saying the new binary was never
// used. Silent no-op upgrades are worse than failed ones.
//
// Loopback only, for the same reason the unclaimed API is loopback only: being on
// the machine is the credential. Handing an exact version to an unauthenticated
// scanner is free targeting information, and this is a security gateway.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{"status": "ok"}
	if isLoopback(r.RemoteAddr) {
		body["version"] = s.version
		// Whether this process is the copy the service manager owns. An install
		// leaves a managed copy at a fixed path precisely so the daemon does not
		// depend on where it was installed from; comparing against it is how a
		// caller tells "the system gateway" from "someone's `serve` in a terminal",
		// which want opposite offers made about them.
		body["managed"] = s.managedBinary
		// The pid, so `install --takeover` can stop whatever is holding the port
		// without hunting for a pid file. Takeover used to depend on one existing,
		// which is not guaranteed — a gateway started in a terminal never writes
		// one — and the failure landed the user back on a command line, which is
		// the whole thing the desktop app exists to avoid. A process that answers
		// here can simply say who it is.
		body["pid"] = os.Getpid()
	}
	writeJSON(w, http.StatusOK, body)
}

// ---- status / mode / auto-block -------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := map[string]any{
		"modes": gateway.Modes,
		"os":    runtime.GOOS,
		// What the UI actually wants to know is "can this gateway do TUN", and
		// "euid == 0" is only the Unix spelling of it: Windows has no euid, and a
		// Linux binary with CAP_NET_ADMIN can do TUN without being root. So the
		// capability is reported directly, and `root` is kept as the raw fact for
		// anything that really means privilege (and for older consoles).
		"root":       paths.Privileged(),
		"privileged": paths.Privileged(),
		"can_tun":    paths.CanTUN(),
	}
	// Dependency status for "optional but recommended" capture features, e.g.
	// Linux TUN auto_redirect (nftables redirect).
	st["nftables"] = doctor.DetectNftables(r.Context(), paths.Privileged())
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
	// Quarantine count belongs on status so every page can surface a loud banner
	// without polling /api/quarantine — operators otherwise mistake a /32 ban for
	// "remote frps/sshd died" (connect then EOF).
	if s.quar != nil {
		st["quarantine"] = len(s.quar.Get().Entries)
	}
	// Which build is running and where its files are. Admin-only, and for the
	// same reason /api/health is loopback-only: an exact version handed to
	// whoever can reach the port is free targeting information, and this is a
	// security gateway. A client has no use for either — the console shows them
	// under Settings → System, which a client cannot open anyway.
	if u := s.caller(r); u != nil && u.Role == users.RoleAdmin {
		st["version"] = s.version
		st["data_dir"] = s.dataDir
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
			writeErr(w, http.StatusBadRequest, modeError(req.Mode, err))
			return
		}
		if to != "" && to != req.Mode {
			resp["revert"] = map[string]any{"to": to, "in_seconds": req.GuardSeconds}
		}
	} else if err := s.mode.SetMode(req.Mode); err != nil {
		writeErr(w, http.StatusBadRequest, modeError(req.Mode, err))
		return
	}
	resp["mode"] = s.mode.Mode()
	writeJSON(w, http.StatusOK, resp)
}

// modeError turns a raw mode-switch failure into a friendly, actionable message.
// A failed TUN switch is almost always a privilege problem (needs root /
// CAP_NET_ADMIN) — the gateway has already reverted to the previous mode, so the
// UI just needs to guide the user, not alarm them with a raw sing-box error.
func modeError(mode string, err error) string {
	if mode != gateway.ModeTUN {
		return err.Error()
	}
	return "TUN mode needs elevated privileges (root / CAP_NET_ADMIN) and a free TUN device. " +
		"The gateway stayed on its previous mode. Details: " + err.Error()
}

func (s *Server) handleConfirmMode(w http.ResponseWriter, r *http.Request) {
	if s.mode == nil {
		writeErr(w, http.StatusServiceUnavailable, "mode controller not available")
		return
	}
	s.mode.ConfirmMode()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAutoBlock is the one-knob shortcut for the same setting the Detection
// page writes as DetectionConfig.AutoBlock — the top bar has a switch, and a
// dedicated endpoint keeps it from having to read-modify-write 25 thresholds
// just to flip one boolean.
//
// It must go through the store, not straight into the engine. It used to do the
// latter, and disposal then came back on by itself at the next restart: the
// engine field was set, nothing on disk was, and ApplyConfig(store) at boot
// resolved AutoBlock from the file. Two writers for one setting where only one
// of them remembers is worse than one writer — the switch looks like it worked.
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
	if s.detcfg == nil {
		// No store wired (a test server, a probe built without one): fall back to
		// the live engine so the switch still does something this run.
		s.detect.SetAutoBlock(req.Enabled)
		writeJSON(w, http.StatusOK, map[string]any{"autoBlock": req.Enabled})
		return
	}
	cfg := s.detcfg.Get()
	cfg.AutoBlock = req.Enabled
	saved, err := s.detcfg.Set(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.detApplier != nil {
		s.detApplier.ApplyDetectionConfig(saved)
	} else {
		s.detect.SetAutoBlock(saved.AutoBlock)
	}
	writeJSON(w, http.StatusOK, map[string]any{"autoBlock": saved.AutoBlock})
}

// Subscriptions leave this process redacted: the URL is a credential, so is
// pasted node text, so is each node's outbound. See subscription.Public.
func (s *Server) handleListSubs(w http.ResponseWriter, r *http.Request) {
	writeArray(w, http.StatusOK, s.store.ListPublic())
}

// Export hands the origin back to an admin who explicitly asked for it, so one
// subscription can be moved to another gateway without reaching into the
// root-owned data directory.
//
// It is a separate endpoint rather than a ?reveal=1 on the list precisely so
// that "the list response carries no credentials" stays unconditional — and so
// that asking for plaintext is a distinct action, not a query string that ends
// up in access logs alongside every ordinary read.
func (s *Server) handleExportSub(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "subscription not found")
		return
	}
	writeJSON(w, http.StatusOK, subscription.Export(sub))
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
		logging.L().Warn().Err(err).Msg("subscription add refresh")
	}
	writeJSON(w, http.StatusCreated, subscription.Public(sub))
}

func (s *Server) handleDeleteSub(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	wasApplied := false
	if sub, ok := s.store.Get(id); ok {
		wasApplied = sub.Applied
	}
	if err := s.store.Delete(id); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if wasApplied && s.applier != nil {
		if err := s.applier.Apply(s.store.AppliedNodes()); err != nil {
			logging.L().Error().Err(err).Msg("re-apply after deleting applied subscription")
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
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
		logging.L().Warn().Err(err).Msg("subscription refresh")
	}
	// Refresh replaces node list in the store; if this sub is live, push the
	// merged applied set so the data plane does not keep stale outbounds.
	if sub.Applied && s.applier != nil {
		if err := s.applier.Apply(s.store.AppliedNodes()); err != nil {
			logging.L().Error().Err(err).Msg("re-apply after subscription refresh")
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		sub, _ = s.store.Get(sub.ID)
	}
	writeJSON(w, http.StatusOK, subscription.Public(sub))
}

func (s *Server) handleApplySub(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "subscription not found")
		return
	}
	if len(sub.Nodes) == 0 {
		// Applying an empty node list collapses the proxy group to
		// selector[direct] (gateway.injectOutbounds) — silently downgrading
		// every route that was going through a real node to direct. A
		// subscription only ever has 0 nodes because its last fetch/parse
		// failed or the link is dead, never because the user wants no exit
		// nodes, so refuse outright rather than let one bad refresh wipe out
		// working routing.
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(
			"refusing to apply %q: it has 0 nodes (last_error=%q) — fix the URL/fetch and refresh first", sub.Name, sub.LastError))
		return
	}
	if s.applier == nil {
		writeErr(w, http.StatusServiceUnavailable, "gateway applier not available")
		return
	}
	// Additive: mark first so AppliedNodes includes this sub, then push the
	// merged set. Roll the flag back if Apply fails so store matches the plane.
	already := sub.Applied
	if !already {
		if err := s.store.SetApplied(sub.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := s.applier.Apply(s.store.AppliedNodes()); err != nil {
		if !already {
			_ = s.store.ClearApplied(sub.ID)
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sub, _ = s.store.Get(sub.ID)
	writeJSON(w, http.StatusOK, subscription.Public(sub))
}

func (s *Server) handleUnapplySub(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "subscription not found")
		return
	}
	if s.applier == nil {
		writeErr(w, http.StatusServiceUnavailable, "gateway applier not available")
		return
	}
	if !sub.Applied {
		writeJSON(w, http.StatusOK, subscription.Public(sub))
		return
	}
	if err := s.store.ClearApplied(sub.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applier.Apply(s.store.AppliedNodes()); err != nil {
		_ = s.store.SetApplied(sub.ID)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sub, _ = s.store.Get(sub.ID)
	writeJSON(w, http.StatusOK, subscription.Public(sub))
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
	// A client sees its own connections and only its own (scope.go).
	writeJSON(w, http.StatusOK, scopeConnections(snap, s.scopeUser(r)))
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
	events := scopeEvents(s.detect.Events(), s.scopeUser(r))
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
	req, ok := decodeListReq(w, r)
	if !ok {
		return
	}
	note := noteArgs(req.Note)
	prev := s.wl.Get() // for rollback if the apply fails
	var (
		rules whitelist.Rules
		err   error
	)
	switch req.Type {
	case "domain":
		if add {
			rules, err = s.wl.AddDomain(req.Value, note...)
		} else {
			rules, err = s.wl.RemoveDomain(req.Value)
		}
	case "ip":
		if add {
			rules, err = s.wl.AddIP(req.Value, note...)
		} else {
			rules, err = s.wl.RemoveIP(req.Value)
		}
	case "process":
		if add {
			rules, err = s.wl.AddProcess(req.Value, note...)
		} else {
			rules, err = s.wl.RemoveProcess(req.Value)
		}
	case "device":
		if add {
			rules, err = s.wl.AddDevice(req.Value, note...)
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
	var apply func(whitelist.Rules) error
	if s.wlApplier != nil {
		apply = s.wlApplier.SetWhitelist
	}
	if applyOrRollback(w, rules, prev, apply, s.wl.Set, "apply whitelist: ") {
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

// ---- blacklist (egress deny-list) -----------------------------------------

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
	req, ok := decodeListReq(w, r)
	if !ok {
		return
	}
	note := noteArgs(req.Note)
	prev := s.bl.Get() // for rollback if the apply fails
	var (
		rules blacklist.Rules
		err   error
	)
	switch req.Type {
	case "domain":
		if add {
			rules, err = s.bl.AddDomain(req.Value, note...)
		} else {
			rules, err = s.bl.RemoveDomain(req.Value)
		}
	case "keyword":
		if add {
			rules, err = s.bl.AddKeyword(req.Value, note...)
		} else {
			rules, err = s.bl.RemoveKeyword(req.Value)
		}
	case "regex":
		if add {
			rules, err = s.bl.AddRegex(req.Value, note...)
		} else {
			rules, err = s.bl.RemoveRegex(req.Value)
		}
	case "ip":
		if add {
			rules, err = s.bl.AddIP(req.Value, note...)
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
	var apply func(blacklist.Rules) error
	if s.blApplier != nil {
		apply = s.blApplier.SetBlacklist
	}
	if applyOrRollback(w, rules, prev, apply, s.bl.Set, "apply blacklist: ") {
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

// ---- directlist (no-proxy / bypass, routing layer) ------------------------

func (s *Server) handleGetDirectlist(w http.ResponseWriter, r *http.Request) {
	if s.dl == nil {
		writeErr(w, http.StatusServiceUnavailable, "directlist not available")
		return
	}
	rules := s.dl.Get()
	// builtin = the gateway's always-on LAN/private ranges, shown read-only so
	// the user sees that LAN never proxies without a footgun to delete them.
	writeJSON(w, http.StatusOK, map[string]any{
		"domains": rules.Domains,
		"ips":     rules.IPs,
		"notes":   rules.Notes,
		"builtin": gateway.PrivateCIDRs(),
	})
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
	req, ok := decodeListReq(w, r)
	if !ok {
		return
	}
	note := noteArgs(req.Note)
	prev := s.dl.Get() // for rollback if the apply fails
	var (
		rules directlist.Rules
		err   error
	)
	switch req.Type {
	case "domain":
		if add {
			rules, err = s.dl.AddDomain(req.Value, note...)
		} else {
			rules, err = s.dl.RemoveDomain(req.Value)
		}
	case "ip":
		if add {
			rules, err = s.dl.AddIP(req.Value, note...)
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
	var apply func(directlist.Rules) error
	if s.dlApplier != nil {
		apply = s.dlApplier.SetDirectList
	}
	if applyOrRollback(w, rules, prev, apply, s.dl.Set, "apply directlist: ") {
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

// writeArray writes a JSON array, never null: an empty slice must serialize as
// [] or every client has to special-case it (this already crashed the Proxies
// page once).
func writeArray[T any](w http.ResponseWriter, code int, items []T) {
	if items == nil {
		items = []T{}
	}
	writeJSON(w, code, items)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, apitypes.ErrorResponse{Error: msg})
}
