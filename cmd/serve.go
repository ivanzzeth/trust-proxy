package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/api"
	"github.com/ivanzzeth/trust-proxy/internal/authn"
	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/detectcfg"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/dnscfg"
	"github.com/ivanzzeth/trust-proxy/internal/endpoints"
	"github.com/ivanzzeth/trust-proxy/internal/finalroute"
	"github.com/ivanzzeth/trust-proxy/internal/gateway"
	"github.com/ivanzzeth/trust-proxy/internal/history"
	"github.com/ivanzzeth/trust-proxy/internal/logging"
	"github.com/ivanzzeth/trust-proxy/internal/netwatch"
	"github.com/ivanzzeth/trust-proxy/internal/nodes"
	"github.com/ivanzzeth/trust-proxy/internal/policymigrate"
	"github.com/ivanzzeth/trust-proxy/internal/posture"
	"github.com/ivanzzeth/trust-proxy/internal/profile"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/subscription"
	"github.com/ivanzzeth/trust-proxy/internal/threatfeed"
	"github.com/ivanzzeth/trust-proxy/internal/tuncfg"
	"github.com/ivanzzeth/trust-proxy/internal/users"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
	"github.com/ivanzzeth/trust-proxy/pkg/clash"
)

var (
	serveConfig        string
	serveExitWithPid   int
	serveAPIAddr       string
	serveDataDir       string
	serveConsoleDir    string
	serveClashAddr     string
	serveClashSecret   string
	serveAPIToken      string
	serveMgmtPorts     string
	serveMode          string
	serveAutoBlock     bool
	serveThreatFeeds   string
	serveThreatRefresh time.Duration
	serveNoThreatFeed  bool
	serveDaemon        bool
	serveLog           string
	servePid           string
	serveLogMaxMB      int
	serveLogKeep       int
	serveLogMaxAge     int
	serveLogCompress   bool

	serveHistoryMaxMB    int
	serveHistoryKeep     int
	serveHistoryMaxAge   int
	serveHistoryCompress bool
)

// daemonLogPath returns the daemon log path the same way for the parent (which
// opens it) and the child (which rotates it): --log, else <data>/serve.log.
func daemonLogPath(dataDir string) string {
	if serveLog != "" {
		return serveLog
	}
	return filepath.Join(dataDir, "serve.log")
}

// embeddedUI holds the dashboard build baked into the binary via go:embed
// (set by SetEmbeddedUI from the root package when built with -tags embed_ui).
// When nil, serve falls back to the on-disk --console dir.
var embeddedUI fs.FS

// SetEmbeddedUI registers the embedded dashboard filesystem.
func SetEmbeddedUI(f fs.FS) { embeddedUI = f }

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the gateway: sing-box data plane + detection + backend API",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := resolveDataDir(serveDataDir)
		if err != nil {
			return err
		}
		serveDataDir = dir // normalize (~/.trust-proxy by default) for the rest of serve
		// Config belongs with the data, not with the checkout: resolve (and on
		// first run seed) <data>/config.json unless -c said otherwise. Done before
		// the daemon re-exec so the child inherits a concrete path.
		cfg, err := resolveConfig(serveConfig, dir)
		if err != nil {
			return err
		}
		serveConfig = cfg
		// Built-in daemon: re-exec detached (survives SSH logout) unless we're
		// already the daemon child.
		if serveDaemon && os.Getenv("TP_DAEMON") == "" {
			logPath, pidPath := daemonLogPath(dir), servePid
			if pidPath == "" {
				pidPath = filepath.Join(dir, "serve.pid")
			}
			return daemonize(logPath, pidPath)
		}
		// Daemon child: fd 1/2 point at the log file the parent opened, so the
		// rotating+async stack has to be installed in here — from this point on
		// everything (ours and sing-box's) goes through the ring (internal/logging).
		if os.Getenv("TP_DAEMON") != "" {
			stop, err := logging.Setup(logging.Options{
				Path:         daemonLogPath(dir),
				MaxSizeMB:    serveLogMaxMB,
				MaxBackups:   serveLogKeep,
				MaxAgeDays:   serveLogMaxAge,
				Compress:     serveLogCompress,
				CaptureStdio: true,
			})
			if err != nil {
				return fmt.Errorf("set up daemon logging: %w", err)
			}
			defer stop()
		}
		return runServe()
	},
}

// resolveDataDir returns the data directory (default ~/.trust-proxy), expanding
// a leading ~, and ensures it exists.
func resolveDataDir(dir string) (string, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".trust-proxy")
	} else if strings.HasPrefix(dir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, dir[2:])
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func init() {
	f := serveCmd.Flags()
	f.StringVarP(&serveConfig, "config", "c", "", "sing-box config path (default <data>/config.json, seeded on first run)")
	f.StringVar(&serveAPIAddr, "api-addr", "127.0.0.1:21585", "trust-proxy backend API listen address")
	f.StringVar(&serveDataDir, "data", "", "data directory (subscriptions, cache, etc.); default ~/.trust-proxy")
	f.StringVar(&serveConsoleDir, "console", "dashboard/dist", "dashboard static dir (shadcn build output)")
	f.StringVar(&serveClashAddr, "clash-addr", "127.0.0.1:21586", "Clash API address (proxied to the console)")
	f.StringVar(&serveClashSecret, "clash-secret", "", "Clash API secret (empty = load/generate a random one in the data dir)")
	f.StringVar(&serveAPIToken, "api-token", "", "require this bearer token on /api/* (probe mode; set when exposing --api-addr on a non-loopback address)")
	f.StringVar(&serveMgmtPorts, "management-ports", "22", "comma-separated ports whose local responses always bypass default-deny (SSH etc.), so TUN/system mode can't lock you out; the API port is added automatically")
	f.StringVar(&serveMode, "mode", gateway.ModeManual, "capture mode: manual | system | tun (tun needs root)")
	f.BoolVar(&serveAutoBlock, "auto-block", true, "auto-drop connections that hit a threat-intel indicator")
	f.StringVar(&serveThreatFeeds, "threat-feeds", "", "comma-separated threat-intel feed URLs (empty = built-in abuse.ch defaults)")
	f.DurationVar(&serveThreatRefresh, "threat-refresh", 12*time.Hour, "threat-intel feed refresh interval")
	f.BoolVar(&serveNoThreatFeed, "no-threat-feed", false, "disable automatic threat-intel feed loading")
	f.BoolVarP(&serveDaemon, "daemon", "d", false, "run in background (detached; survives SSH logout)")
	f.StringVar(&serveLog, "log", "", "daemon log file (default <data>/serve.log)")
	f.StringVar(&servePid, "pid", "", "daemon pid file (default <data>/serve.pid)")
	f.IntVar(&serveExitWithPid, "exit-with-pid", 0, "shut down when this pid exits (used by the desktop shell so a force-quit leaves no orphan gateway)")
	f.IntVar(&serveLogMaxMB, "log-max-size", logging.DefaultMaxSizeMB, "rotate the daemon log past this many MB (0 = never rotate)")
	f.IntVar(&serveLogKeep, "log-keep", logging.DefaultMaxBackups, "how many rotated daemon logs to keep")
	f.IntVar(&serveLogMaxAge, "log-max-age", 0, "delete rotated daemon logs older than this many days (0 = keep by count only)")
	f.BoolVar(&serveLogCompress, "log-compress", true, "gzip rotated daemon logs")
	f.IntVar(&serveHistoryMaxMB, "history-max-size", 32, "rotate the connection history past this many MB")
	f.IntVar(&serveHistoryKeep, "history-keep", 2, "how many rotated history files to keep (still browsable in the History view)")
	f.IntVar(&serveHistoryMaxAge, "history-max-age", 0, "delete rotated history older than this many days (0 = keep by count only)")
	f.BoolVar(&serveHistoryCompress, "history-compress", true, "gzip rotated history files")
}

func runServe() error {
	secret, err := resolveClashSecret(serveDataDir)
	if err != nil {
		return err
	}

	if err := policymigrate.Run(serveDataDir); err != nil {
		logging.L().Warn().Err(err).Msg("policy migrate")
	}

	wlStore, err := whitelist.NewStore(serveDataDir + "/whitelist.json")
	if err != nil {
		return err
	}

	blStore, err := blacklist.NewStore(serveDataDir + "/blacklist.json")
	if err != nil {
		return err
	}

	dlStore, err := directlist.NewStore(serveDataDir + "/directlist.json")
	if err != nil {
		return err
	}

	crStore, err := customrules.NewStore(serveDataDir + "/customrules.json")
	if err != nil {
		return err
	}

	pgStore, err := proxygroups.NewStore(serveDataDir + "/proxygroups.json")
	if err != nil {
		return err
	}

	rsStore, err := ruleset.NewStore(serveDataDir + "/rulesets.json")
	if err != nil {
		return err
	}
	// Off the hot path: decode enabled permit-granting rule sets (Slack/Notion/
	// China-wide/… packs whose Permit comes entirely from a rule-set role) into
	// the in-memory index ruleset.MatchesPermit queries. See SetTrustedDest below.
	go ruleset.WarmPermitCache(rsStore.Get(), nil)

	engine := detect.New(2000)
	engine.SetAutoBlock(serveAutoBlock)

	// Durable per-connection history: fold every completed connection into an
	// append-only log + aggregates.
	histStore, err := history.NewStoreWithOptions(filepath.Join(serveDataDir, "history.jsonl"), history.Options{
		MaxSizeMB:  serveHistoryMaxMB,
		MaxBackups: serveHistoryKeep,
		MaxAgeDays: serveHistoryMaxAge,
		Compress:   serveHistoryCompress,
	})
	if err != nil {
		return err
	}
	defer histStore.Close()
	engine.SetOnFinalize(histStore.Record)

	detCfgStore, err := detectcfg.NewStore(filepath.Join(serveDataDir, "detection.json"))
	if err != nil {
		return err
	}
	engine.ApplyConfig(detCfgStore.Get())
	// Disposal waits for the Permit index: it is built asynchronously and fetches
	// remote rule sets, so until it lands every rule-set-derived Permit reads as
	// "not permitted" — banning a destination the operator had in fact approved.
	engine.SetDisposalReady(func() bool {
		return !detCfgStore.Get().RequireWarmPermit || ruleset.PermitCacheWarm()
	})

	quarStore, err := quarantine.NewStore(filepath.Join(serveDataDir, "quarantine.json"))
	if err != nil {
		return err
	}

	// Host-level observation: routes and interface scope. Two bypasses never
	// touch the data plane — a rogue DHCP route (TunnelVision) and a network
	// claiming public space is "local" (TunnelCrack LocalNet) — so the gateway
	// has to look at the machine to see them. Read-only: findings are reported,
	// nothing is enforced.
	netWatcher := netwatch.New(func(f netwatch.Finding) {
		logging.L().Warn().Str("kind", f.Kind).Str("detail", f.Detail).Msg("network integrity")
		engine.EmitDetection(detect.Detection{
			Kind: detect.KindRoute, Action: detect.ActionAlert,
			Host: f.Route.Prefix.String(), Destination: f.Route.Interface,
			Reasons: []string{f.Detail},
		})
	})
	engine.SetLocalNetCheck(netWatcher.IsLocal)
	netWatcher.SetDialedCheck(engine.DialedDestination)
	netWatcher.SetReportHostRoutes(detCfgStore.Get().RouteWatchHostRoutes)
	defer netWatcher.Stop()

	detStore, err := detect.NewStore(filepath.Join(serveDataDir, "detections.jsonl"))
	if err != nil {
		return err
	}
	defer detStore.Close()
	engine.SetOnDetection(detStore.Record)
	// Static demo indicators (always on, for testing); the live feed adds to these.
	engine.LoadThreats([]string{"malware.test", "c2.example.com"}, nil)

	// Large upload to a destination that is NOT permitted (whitelist OR
	// pack/custom Permit rules OR a rule-set role granting Permit) is treated
	// as exfil when auto-block is on. Packs like Cursor/Slack/Notion/China-wide
	// open the ACL gate via customrules or via a permit-role rule set — both
	// must count as trusted here, or a legitimate upload to a pack's domains
	// gets wrongly auto-blocked/banned as exfiltration.
	engine.SetTrustedDest(func(host, dest string) bool {
		if whitelist.Matches(wlStore.Get(), host, dest) {
			return true
		}
		if customrules.MatchesPermit(crStore.Get(), host, dest) {
			return true
		}
		return ruleset.MatchesPermit(host, dest)
	})

	// Restore the persisted audit log so events survive a restart.
	eventsPath := filepath.Join(serveDataDir, "events.json")
	if b, err := os.ReadFile(eventsPath); err == nil {
		var saved []detect.Event
		if json.Unmarshal(b, &saved) == nil {
			engine.RestoreEvents(saved)
			logging.L().Info().Int("count", len(saved)).Str("path", eventsPath).Msg("restored detection events")
		}
	}

	// Auto-load public threat-intel feeds (abuse.ch etc.) in the background.
	feedCtx, feedCancel := context.WithCancel(context.Background())
	defer feedCancel()
	if !serveNoThreatFeed {
		var feeds []string
		if serveThreatFeeds != "" {
			for _, u := range strings.Split(serveThreatFeeds, ",") {
				if u = strings.TrimSpace(u); u != "" {
					feeds = append(feeds, u)
				}
			}
		}
		loader := threatfeed.New(engine, feeds, serveThreatRefresh, logging.Printf)
		go loader.Run(feedCtx)
	}

	profStore, err := profile.NewStore(serveDataDir + "/profiles.json")
	if err != nil {
		return err
	}
	dnsStore, err := dnscfg.NewStore(serveDataDir + "/dns.json")
	if err != nil {
		return err
	}
	nodesStore, err := nodes.NewStore(serveDataDir + "/nodes.json")
	if err != nil {
		return err
	}
	userStore, err := users.NewStore(serveDataDir + "/users.json")
	if err != nil {
		return err
	}
	auth, err := authn.New(serveDataDir)
	if err != nil {
		return err
	}
	tunStore, err := tuncfg.NewStore(serveDataDir + "/tun.json")
	if err != nil {
		return err
	}
	epStore, err := endpoints.NewStore(serveDataDir + "/endpoints.json")
	if err != nil {
		return err
	}
	finalStore, err := finalroute.NewStore(serveDataDir + "/final.json")
	if err != nil {
		return err
	}
	postureStore, err := posture.NewStore(serveDataDir + "/posture.json")
	if err != nil {
		return err
	}

	store, err := subscription.NewStore(serveDataDir + "/subscriptions.json")
	if err != nil {
		return err
	}

	mgr := gateway.NewManager(serveConfig, serveDataDir, wlStore.Get(), engine, secret)
	// Under --daemon this is the async ring (logging.Setup); in the foreground it
	// is nil and sing-box keeps writing to the terminal.
	mgr.SetLogWriter(logging.Sink())
	mgr.SetInitialMode(serveMode)
	mgr.SetInitialPosture(postureStore.Active())
	mgr.SetInitialFinal(finalStore.Get().Outbound)
	mgr.SetInitialBlacklist(blStore.Get())
	mgr.SetInitialQuarantine(quarStore.Get())
	mgr.SetInitialDirectList(dlStore.Get())
	mgr.SetInitialCustomRules(crStore.Get())
	mgr.SetInitialProxyGroups(pgStore.Get())
	mgr.SetInitialRuleSets(rsStore.Get())
	mgr.SetInitialDNS(dnsStore.Get())
	// Proxy-inbound credentials are derived from the user registry: each account
	// may carry a proxy password, and an empty result leaves the inbound open.
	mgr.SetInitialInbound(apitypes.InboundAuth{Users: userStore.ProxyCredentials()})
	mgr.SetInitialTUN(tunStore.Get())
	mgr.SetInitialEndpoints(epStore.All())
	// In TUN mode the gateway captures ALL of this machine's outbound traffic,
	// including this store's OWN subscription-fetch HTTP client — which has
	// nothing to do with sing-box's internal dialer. Without an explicit
	// permit+direct route for the subscription host, that fetch gets routed
	// through whichever proxy node is currently applied instead of this
	// machine's real network path, and some subscription providers detect
	// "this looks like a VPN/proxy request" and refuse to serve real node
	// data. Ensure the host is permitted + routed direct before every fetch
	// (idempotent: skips the rebuild entirely once already set).
	//
	// The connection route alone used to not be enough: a direct-routed
	// *domain* destination still re-resolves via sing-box's global
	// default_domain_resolver, which is commonly detour="proxy" (anti-leak/
	// anti-poisoning) — so the fetch could still hang through a dead proxy
	// node even after routing correctly. Fixed generally (not just for this
	// host) by giving the "direct" outbound its own domain_resolver — see
	// gateway_dns.go's injectDirectDomainResolver — so this callback only
	// needs to handle the permit+route side.
	store.SetEnsureReachable(func(host string) error {
		host = strings.ToLower(host)
		wl := wlStore.Get()
		dl := dlStore.Get()
		if sliceHasFold(wl.Domains, host) && sliceHasFold(dl.Domains, host) {
			return nil
		}
		if !sliceHasFold(wl.Domains, host) {
			if _, err := wlStore.AddDomain(host); err != nil {
				return err
			}
		}
		if !sliceHasFold(dl.Domains, host) {
			if _, err := dlStore.AddDomain(host); err != nil {
				return err
			}
		}
		if err := mgr.SetWhitelist(wlStore.Get()); err != nil {
			return err
		}
		return mgr.SetDirectList(dlStore.Get())
	})
	mgr.SetInitialManagementPorts(managementPorts(serveMgmtPorts, serveAPIAddr))
	// Auto-ban sink: threat-intel / non-permitted large upload → blacklist + hot reload.
	// What the gateway blocks by itself goes to the quarantine list, not the
	// operator's deny list: deny lives in the posture slot, so a Strict<->Split
	// switch or a profile activation would silently un-block it.
	engine.SetOnBan(func(domain, ip, reason string) {
		list, err := quarStore.Add(domain, ip, reason)
		if err != nil {
			logging.L().Error().Err(err).Str("domain", domain).Str("ip", ip).Msg("quarantine add")
			return
		}
		logging.L().Warn().Str("domain", domain).Str("ip", ip).Str("reason", reason).Msg("quarantined")
		if err := mgr.SetQuarantine(list); err != nil {
			logging.L().Error().Err(err).Msg("quarantine apply")
		}
	})
	// Re-apply the previously-applied subscription so a restart/upgrade keeps the
	// exit node instead of dropping to a direct-only proxy group (which is "no
	// net" on a box whose only egress is the node).
	for _, sub := range store.List() {
		if sub.Applied && len(sub.Nodes) > 0 {
			mgr.SetInitialNodes(sub.Nodes)
			logging.L().Info().Str("subscription", sub.Name).Int("nodes", len(sub.Nodes)).Msg("re-applying subscription on startup")
			break
		}
	}
	// Baseline the routing table once the data plane is up, so the routes the
	// gateway itself installs are "expected" and only later arrivals are reported.
	syncNetWatch := func() {
		active := mgr.Mode() == gateway.ModeTUN
		netWatcher.SetTunnelActive(active, gateway.TunPrefixes())
	}
	mgr.SetOnRebuild(syncNetWatch)

	if err := mgr.Start(); err != nil {
		return err
	}
	defer mgr.Close()
	apiSrv := api.NewServer(api.Options{
		Addr:         serveAPIAddr,
		Store:        store,
		Applier:      mgr,
		Whitelist:    wlStore,
		WLApplier:    mgr,
		Blacklist:    blStore,
		BLApplier:    mgr,
		Directlist:   dlStore,
		DLApplier:    mgr,
		QueryStats:   engine,
		NetState:     netWatcher,
		Fingerprints: engine,
		Detection:    detCfgStore,
		DetApplier:   detectApplier{engine},
		Quarantine:   quarStore,
		QuarApplier:  quarantineApplier{mgr},
		CustomRules:  crStore,
		CRApplier:    mgr,
		RulesView:    mgr,
		ProxyGroups:  pgStore,
		PGApplier:    mgr,
		Detect:       engine,
		Mode:         mgr,
		RuleSets:     rsStore,
		RSApplier:    mgr,
		Profiles:     profStore,
		ProfApplier:  mgr,
		Posture:      postureStore,
		Final:        finalStore,
		FinalApplier: mgr,
		DNS:          dnsStore,
		DNSApplier:   mgr,
		Users:        userStore,
		Authn:        auth,
		DataDir:      serveDataDir,
		InbApplier:   mgr,
		TUN:          tunStore,
		TUNApplier:   mgr,
		Endpoints:    epStore,
		EPApplier:    mgr,
		History:      histStore,
		Detections:   detStore,
		Nodes:        nodesStore,
		Token:        serveAPIToken,
		Clash:        clash.New(serveClashAddr, secret),
		ConsoleDir:   serveConsoleDir,
		ConsoleFS:    embeddedUI,
	})
	apiSrv.SyncActivePostureSlot()
	go func() {
		if err := apiSrv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logging.L().Error().Err(err).Msg("backend api")
		}
	}()
	defer apiSrv.Close()

	syncNetWatch()
	if secs := detCfgStore.Get().RouteWatchSec; secs > 0 && netwatch.RouteWatchSupported() {
		netWatcher.Start(time.Duration(secs) * time.Second)
	}

	logging.L().Info().Str("api", serveAPIAddr).Msg("gateway up")
	logging.L().Info().Str("url", "http://"+serveAPIAddr+"/").Msg("dashboard")
	announceBootstrap(userStore, auth, serveDataDir, serveAPIAddr)
	logging.L().Info().Str("mode", mgr.Mode()).Bool("auto_block", serveAutoBlock).Msg("capture mode")

	// Persist the audit log periodically so a crash loses at most one interval.
	// Written to a temp file and renamed: os.WriteFile truncates first, so a crash
	// mid-write left a half-written file that the restore path then discarded —
	// losing the whole ring rather than one interval. Skipped entirely when
	// nothing changed, which on an idle gateway is most ticks (the ring is ~650 KB
	// and this runs every 30s).
	var lastSaved uint64
	saveEvents := func() {
		events := engine.Events()
		var seq uint64
		if n := len(events); n > 0 {
			seq = events[n-1].ID
		}
		if seq == lastSaved {
			return
		}
		b, err := json.Marshal(events)
		if err != nil {
			return
		}
		tmp := eventsPath + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return
		}
		if err := os.Rename(tmp, eventsPath); err != nil {
			_ = os.Remove(tmp)
			return
		}
		lastSaved = seq
	}
	stopSave := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopSave:
				return
			case <-t.C:
				saveEvents()
			}
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	// --exit-with-pid: shut down when the process that started us disappears, so a
	// force-quit of the desktop shell cannot leave the data plane running behind
	// its back (the shell's own exit handler never runs on SIGKILL).
	if serveExitWithPid > 0 {
		stopWatch := watchParent(serveExitWithPid, parentWatchInterval, func() {
			logging.L().Info().Int("parent", serveExitWithPid).Msg("parent process gone; shutting down")
			signals <- syscall.SIGTERM
		})
		defer stopWatch()
	}
	<-signals
	logging.L().Info().Msg("shutting down")
	close(stopSave)
	saveEvents()
	return nil
}

// announceBootstrap tells the operator how to claim an unclaimed gateway.
//
// Until the first admin exists the API is open — it has to be, or a fresh install
// could never be set up — so this says so out loud rather than leaving it
// implicit. On a machine with no browser (the usual remote gateway) the CLI path
// is the answer; when the API is exposed off-loopback the network path
// additionally needs the one-time code printed here, so that whoever reaches the
// port first cannot simply claim it.
func announceBootstrap(store *users.Store, auth *authn.Authn, dataDir, apiAddr string) {
	if store == nil || !store.Empty() {
		return
	}
	log := logging.L()
	log.Warn().Msg("no accounts yet: this gateway is UNCLAIMED and its API is open until you create the first admin")
	log.Info().Msgf("  on this machine:  trust-proxy user add <name> --admin --data %s", dataDir)
	log.Info().Msgf("  or in a browser:  http://%s/", apiAddr)
	if auth == nil || loopbackAddr(apiAddr) {
		return
	}
	code, err := auth.BootstrapCode(dataDir)
	if err != nil {
		log.Error().Err(err).Msg("generate bootstrap code")
		return
	}
	log.Warn().Msgf("  API is reachable off-loopback: remote bootstrap needs this one-time code: %s", code)
	log.Info().Msgf("  trust-proxy auth bootstrap --api-addr %s --code %s", apiAddr, code)
}

// loopbackAddr reports whether a listen address only accepts local connections.
func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sliceHasFold reports whether ss contains want, case-insensitively.
func sliceHasFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// managementPorts parses the --management-ports csv and always appends the API
// port, so remote management (SSH + the console/API) survives a TUN/system-proxy
// capture under default-deny.
func managementPorts(csv, apiAddr string) []int {
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if p > 0 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, s := range strings.Split(csv, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			add(n)
		}
	}
	if i := strings.LastIndex(apiAddr, ":"); i >= 0 {
		if p, err := strconv.Atoi(apiAddr[i+1:]); err == nil {
			add(p)
		}
	}
	return out
}

// resolveClashSecret returns the --clash-secret flag if set, else a secret
// persisted in <dataDir>/clash-secret (generating a random one on first run).
func resolveClashSecret(dataDir string) (string, error) {
	if serveClashSecret != "" {
		return serveClashSecret, nil
	}
	path := filepath.Join(dataDir, "clash-secret")
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(buf)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		return "", err
	}
	return secret, nil
}

// detectApplier pushes tuned thresholds into the live engine (no rebuild: the
// detectors read them under their own lock).
type detectApplier struct{ engine *detect.Engine }

func (d detectApplier) ApplyDetectionConfig(c apitypes.DetectionConfig) { d.engine.ApplyConfig(c) }

// quarantineApplier rebuilds the data plane after a release, so the reject rules
// match the list.
type quarantineApplier struct{ mgr *gateway.Manager }

func (q quarantineApplier) ApplyQuarantine(l quarantine.List) error { return q.mgr.SetQuarantine(l) }
