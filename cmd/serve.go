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
	"github.com/ivanzzeth/trust-proxy/internal/modecfg"
	"github.com/ivanzzeth/trust-proxy/internal/netwatch"
	"github.com/ivanzzeth/trust-proxy/internal/nodes"
	"github.com/ivanzzeth/trust-proxy/internal/paths"
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
	serveConfig         string
	serveWindowsService bool
	serveExitWithPid    int
	serveDumpConfig     string
	serveAPIAddr        string
	serveDataDir        string
	serveConsoleDir     string
	serveClashAddr      string
	serveClashSecret    string
	serveAPIToken       string
	serveMgmtPorts      string
	serveMode           string
	serveAutoBlock      bool
	serveThreatFeeds    string
	serveThreatRefresh  time.Duration
	serveNoThreatFeed   bool
	serveDaemon         bool
	serveLog            string
	servePid            string
	serveLogMaxMB       int
	serveLogKeep        int
	serveLogMaxAge      int
	serveLogCompress    bool

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

// serve runs the gateway in the foreground. It is what the service manager
// execs, and it is hidden from the command list on purpose: a human installs the
// gateway with `trust-proxy install` and never types this. Leaving it advertised
// is how people ended up with a second, unprivileged, TUN-less gateway.
var serveCmd = &cobra.Command{
	Use:    "serve",
	Short:  "Run the gateway in the foreground (what the system service execs; use `install`)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Before anything is created — including by the daemon re-exec, and by
		// sing-box, which writes cache.db and the Tailscale state itself.
		tightenUmask()
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
		// A Windows service is not just "a process the SCM starts": it has to
		// report Running and handle Stop over the SCM protocol, or the SCM kills
		// it when its start timeout expires. runWindowsService wraps runServe in
		// that protocol; everything else about the gateway is identical.
		if serveWindowsService {
			return runWindowsService(runServe)
		}
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

// resolveConsoleDir turns --console into an absolute path and says something when
// there is no console to serve at all.
//
// The default is a *relative* path, which is right for `make dashboard && ./trust-proxy
// serve` in a checkout and meaningless anywhere else: an installed service runs
// with cwd = /usr/local/libexec (or C:\), so the relative default resolves to
// nothing and the console answers "dashboard not built" — after the install said
// it succeeded. Measured on a real install, not hypothetical.
//
// Absolutising here also means the daemon keeps working if anything later changes
// its working directory.
func resolveConsoleDir() string {
	if embeddedUI != nil {
		return serveConsoleDir // the embedded build wins; the path is unused
	}
	dir := paths.ExpandHome(serveConsoleDir)
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		// Not fatal — the API is the point and plenty of gateways are headless —
		// but it must be said at startup rather than discovered as a blank page.
		logging.L().Warn().Str("console", dir).
			Msg("no console here and none embedded: / will say \"dashboard not built\" " +
				"(build with `make build-embed`, or point --console at a dashboard/dist)")
	}
	return dir
}

// resolveDataDir returns the machine-wide data directory, expanding a leading ~
// on an explicit override, and ensures it exists.
//
// There is one data directory and it is machine-wide, because there is one
// gateway and it runs as root under the service manager. The per-user default
// this used to have (~/.trust-proxy) is gone: it produced a second gateway that
// could not do TUN, and when anyone ran it with sudo it left a root-owned
// directory in a home that the unprivileged desktop app could no longer write.
//
// --data survives as an operator/test override, not as a deployment shape.
func resolveDataDir(dir string) (string, error) {
	explicit := dir != ""
	if !explicit {
		dir = paths.Data()
	} else {
		dir = paths.ExpandHome(dir)
	}
	if err := os.MkdirAll(dir, dataDirMode); err != nil {
		if os.IsPermission(err) && !paths.Privileged() {
			return "", notYourGatewayError(dir)
		}
		return "", err
	}
	// MkdirAll leaves an existing directory's mode alone, so every machine
	// installed before this was tightened keeps 0755 — and those are the machines
	// with the most policy in there.
	if tightenDataDir(dir) {
		logging.L().Info().Str("dir", dir).Msg("narrowed the data directory to owner-only")
	}
	// The service manager, not us, creates the log file — see tightenLogFile.
	tightenLogFile(daemonLogPath(dir))
	// Existing but unwritable is the case that matters, and MkdirAll says nothing
	// about it: once the service has run, /var/lib/trust-proxy is there and owned
	// by root, so an unprivileged `serve` sails past the check above and dies
	// several steps later on "open …/clash-secret: permission denied" — an errno
	// about a file nobody has heard of, for a command they should not be running.
	// Measured in the Linux e2e.
	if err := writable(dir); err != nil {
		if !paths.Privileged() {
			return "", notYourGatewayError(dir)
		}
		return "", fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	return dir, nil
}

// notYourGatewayError is what an ordinary user gets for running the daemon by
// hand. There is exactly one supported way to put a gateway on a machine, and
// naming it is more use than any permission error.
func notYourGatewayError(dir string) error {
	return fmt.Errorf("cannot write to %s — that directory belongs to the system gateway, and this is not root.\n\n"+
		"`serve` is what the service manager runs. You almost certainly want:\n"+
		"    sudo %s install\n\n"+
		"which sets the gateway up as a system service: root, starts at boot, survives logout,\n"+
		"and can capture all traffic with TUN. To run a throwaway gateway somewhere else, pass --data.",
		dir, os.Args[0])
}

// writable reports whether this process can actually create files in dir.
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".writable-")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func init() {
	f := serveCmd.Flags()
	f.StringVarP(&serveConfig, "config", "c", "", "sing-box config path (default <data>/config.json, seeded on first run)")
	f.StringVar(&serveAPIAddr, "api-addr", "127.0.0.1:21585", "trust-proxy backend API listen address")
	f.StringVar(&serveDataDir, "data", "", "data directory override (default: the machine-wide one, "+paths.Data()+")")
	f.StringVar(&serveConsoleDir, "console", "dashboard/dist", "dashboard static dir (shadcn build output)")
	f.StringVar(&serveClashAddr, "clash-addr", "127.0.0.1:21586", "Clash API address (proxied to the console)")
	f.StringVar(&serveClashSecret, "clash-secret", "", "Clash API secret (empty = load/generate a random one in the data dir)")
	f.StringVar(&serveAPIToken, "api-token", "", "require this bearer token on /api/* (probe mode; set when exposing --api-addr on a non-loopback address)")
	f.StringVar(&serveMgmtPorts, "management-ports", "22", "comma-separated ports whose local responses always bypass default-deny (SSH etc.), so TUN/system mode can't lock you out; the API port is added automatically")
	// Empty default = whatever the mode store says, the same way posture, final and
	// every other axis works. It used to default to "manual", a non-empty value
	// that was applied unconditionally on every boot, so the mode could only ever
	// come from this flag — which is why switching to TUN from the console lasted
	// until the next restart. As an explicit override it still works, for ops and
	// tests, like --data.
	f.StringVar(&serveMode, "mode", "", "capture mode override: manual | system | tun (empty = the stored mode; tun needs root)")
	f.BoolVar(&serveAutoBlock, "auto-block", true, "auto-drop connections that hit a threat-intel indicator")
	f.StringVar(&serveThreatFeeds, "threat-feeds", "", "comma-separated threat-intel feed URLs (empty = built-in abuse.ch defaults)")
	f.DurationVar(&serveThreatRefresh, "threat-refresh", 12*time.Hour, "threat-intel feed refresh interval")
	f.BoolVar(&serveNoThreatFeed, "no-threat-feed", false, "disable automatic threat-intel feed loading")
	f.BoolVarP(&serveDaemon, "daemon", "d", false, "run in background (detached; survives SSH logout)")
	f.BoolVar(&serveWindowsService, "windows-service", false, "run under the Windows Service Control Manager (set by `service install`; not for interactive use)")
	_ = f.MarkHidden("windows-service")
	f.StringVar(&serveLog, "log", "", "daemon log file (default <data>/serve.log)")
	f.StringVar(&servePid, "pid", "", "daemon pid file (default <data>/serve.pid)")
	f.StringVar(&serveDumpConfig, "dump-config", "", "write the merged sing-box config here on every rebuild (debugging: the running config is assembled in memory)")
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
	modeStore, err := modecfg.NewStore(serveDataDir + "/mode.json")
	if err != nil {
		return err
	}

	store, err := subscription.NewStore(serveDataDir + "/subscriptions.json")
	if err != nil {
		return err
	}

	mgr := gateway.NewManager(serveConfig, serveDataDir, wlStore.Get(), engine, secret, serveClashAddr)
	// One finalize sink, two consumers. The detection engine already resolves
	// Event.Outbound down to the real group member (socks/gw-cloud, not "proxy"),
	// so the throughput term costs no new plumbing in the data plane — only the
	// closed connections we were already recording.
	engine.SetOnFinalize(func(ev detect.Event) {
		histStore.Record(ev)
		if ev.DurationMS > 0 {
			mgr.RecordTransfer(ev.Outbound, ev.Upload+ev.Download, time.Duration(ev.DurationMS)*time.Millisecond)
		}
	})
	// Under --daemon this is the async ring (logging.Setup); in the foreground it
	// is nil and sing-box keeps writing to the terminal.
	mgr.SetLogWriter(logging.Sink())
	// An explicit --mode wins for this run and is recorded, so the flag and the
	// store never disagree afterwards; otherwise the stored mode is authoritative.
	// A flag that overrode the store on every boot would reintroduce the bug with
	// the sign flipped: the console switch would apply and then be undone.
	if mode, err := resolveMode(serveMode, modeStore); err != nil {
		return err
	} else {
		mgr.SetInitialMode(mode)
	}
	mgr.SetModePersister(func(mode string) error {
		_, err := modeStore.Set(mode)
		return err
	})
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
	// Gateways registered as exits are outbound nodes to the data plane; feeding
	// them before the first Start() means an exit survives a restart without
	// waiting for the console to touch anything.
	mgr.SetInitialGatewayExits(nodesStore.ExitNodes())
	// In client mode this instance captures local traffic but leaves enforcement to
	// the gateway it exits through.
	mgr.SetInitialClientMode(nodesStore.LocalMode() == nodes.ModeClient)
	if serveDumpConfig != "" {
		mgr.SetDumpConfigPath(serveDumpConfig)
	}
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
	mgmt, err := managementPortsChecked(serveMgmtPorts, serveAPIAddr)
	if err != nil {
		// Refused at startup rather than warned about: this flag decides what is exempt
		// from every security layer, so a value that widens it unpredictably is worth
		// not starting over.
		return err
	}
	mgr.SetInitialManagementPorts(mgmt)
	// Auto-ban sink: threat-intel / non-permitted large upload → blacklist + hot reload.
	// What the gateway blocks by itself goes to the quarantine list, not the
	// operator's deny list: deny lives in the posture slot, so a Strict<->Split
	// switch or a profile activation would silently un-block it.
	engine.SetOnBan(func(domain, ip, reason string) {
		list, err := quarStore.Add(domain, ip, reason)
		if err != nil {
			// Partial success is still success: Add reports a rejected value while
			// keeping the valid one, and the connection is already dead. Log and
			// carry on to apply, or the surviving entry never reaches the data
			// plane and never shows up in the console.
			logging.L().Error().Err(err).Str("domain", domain).Str("ip", ip).Msg("quarantine add")
			if len(list.Entries) == 0 {
				return
			}
		}
		logging.L().Warn().Str("domain", domain).Str("ip", ip).Str("reason", reason).Msg("quarantined")
		if err := mgr.SetQuarantine(list); err != nil {
			logging.L().Error().Err(err).Msg("quarantine apply")
		}
	})
	// Re-apply every previously-applied subscription so a restart/upgrade keeps
	// the merged exit set (multi-airport HA) instead of dropping to direct-only.
	if nodes := store.AppliedNodes(); len(nodes) > 0 {
		mgr.SetInitialNodes(nodes)
		nApplied := 0
		for _, sub := range store.List() {
			if sub.Applied {
				nApplied++
			}
		}
		logging.L().Info().Int("subscriptions", nApplied).Int("nodes", len(nodes)).Msg("re-applying subscriptions on startup")
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
	// Persist scores periodically as well as at exit: a kill -9 (which the
	// service manager's KeepAlive makes routine) would otherwise put every node
	// back into warm-up, and the first ten dials after a crash are exactly when
	// knowing which node is dead matters most.
	scoreFlush := time.NewTicker(2 * time.Minute)
	defer scoreFlush.Stop()
	go func() {
		for range scoreFlush.C {
			_ = mgr.FlushScores()
		}
	}()
	defer func() { _ = mgr.FlushScores() }()

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
		GWApplier:    mgr,
		CMApplier:    mgr,
		Token:        serveAPIToken,
		Version:      version,
		Clash:        clash.New(serveClashAddr, secret),
		ConsoleDir:   resolveConsoleDir(),
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
	// Two ways to be told to stop: a signal (a human, an init system, the parent
	// watch) or the Windows SCM, which does not use signals at all.
	select {
	case <-signals:
	case <-stopRequested:
	}
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
	// Two lines, because claiming is only half of it: the account exists but the
	// CLI is still anonymous, and the next command would answer "unauthorized".
	log.Info().Msgf("  on this machine:  trust-proxy auth bootstrap <name>")
	log.Info().Msgf("  then, for the CLI: eval \"$(trust-proxy auth login <name> | grep ^export)\"")
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
	// <name> is not decoration. The CLI takes the username positionally, so a line
	// printed without it invites pasting the code into that slot — which claims the
	// gateway under an account named after the code, and succeeds. That happened to
	// a real user, from this very line.
	log.Info().Msgf("  trust-proxy auth bootstrap <name> --api-addr %s --code %s", apiAddr, code)
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
// ephemeralFloor is the lowest port the kernel hands out to outgoing connections
// on the platforms we run on: Linux defaults to 32768-60999, macOS to 49152-65535,
// Windows to 49152-65535. The lowest of those is the safe line to draw.
//
// A management port inside that range is not a listener you chose, it is a number
// the OS will assign to arbitrary *outbound* connections — and a source_port rule
// at the top of the floor then exempts those connections from the blacklist,
// quarantine, the process and device gates and the Permit gate, at whatever rate
// the OS happens to reuse it. Nothing checked, and 50000 does not look wrong.
const ephemeralFloor = 32768

// managementPortsChecked parses the --management-ports csv and refuses a value that
// would punch an unpredictable hole rather than a deliberate one.
//
// The API port is appended unconditionally and exempt from the check: the operator
// chose it, it is a listener rather than an allocation, and refusing it would stop
// the gateway from starting instead of warning about a flag.
func managementPortsChecked(csv, apiAddr string) ([]int, error) {
	for _, s := range strings.Split(csv, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("--management-ports: %q is not a port number", s)
		}
		if n <= 0 || n > 65535 {
			return nil, fmt.Errorf("--management-ports: %d is not a port number", n)
		}
		if n >= ephemeralFloor {
			return nil, fmt.Errorf("--management-ports: refusing %d because it is in the "+
				"ephemeral range (%d and above), which the kernel assigns to outgoing "+
				"connections — a rule on it would exempt arbitrary outbound traffic from the "+
				"blacklist, quarantine and the Permit gate. Use the port your service listens "+
				"on (22 for SSH)", n, ephemeralFloor)
		}
	}
	return managementPorts(csv, apiAddr), nil
}

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
	if err := os.MkdirAll(dataDir, dataDirMode); err != nil {
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
