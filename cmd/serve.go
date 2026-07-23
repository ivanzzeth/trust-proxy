package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
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
	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
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
	"github.com/ivanzzeth/trust-proxy/internal/threatfeed"
	"github.com/ivanzzeth/trust-proxy/internal/tuncfg"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/clash"
)

var (
	serveConfig        string
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
)

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
		// Built-in daemon: re-exec detached (survives SSH logout) unless we're
		// already the daemon child.
		if serveDaemon && os.Getenv("TP_DAEMON") == "" {
			logPath, pidPath := serveLog, servePid
			if logPath == "" {
				logPath = filepath.Join(dir, "serve.log")
			}
			if pidPath == "" {
				pidPath = filepath.Join(dir, "serve.pid")
			}
			return daemonize(logPath, pidPath)
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
	f.StringVarP(&serveConfig, "config", "c", "configs/config.json", "sing-box config path")
	f.StringVar(&serveAPIAddr, "api-addr", "127.0.0.1:9096", "trust-proxy backend API listen address")
	f.StringVar(&serveDataDir, "data", "", "data directory (subscriptions, cache, etc.); default ~/.trust-proxy")
	f.StringVar(&serveConsoleDir, "console", "dashboard/dist", "dashboard static dir (shadcn build output)")
	f.StringVar(&serveClashAddr, "clash-addr", "127.0.0.1:9090", "Clash API address (proxied to the console)")
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
}

func runServe() error {
	secret, err := resolveClashSecret(serveDataDir)
	if err != nil {
		return err
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

	engine := detect.New(2000)
	engine.SetAutoBlock(serveAutoBlock)

	// Durable per-connection history: fold every completed connection into an
	// append-only log + aggregates.
	histStore, err := history.NewStore(filepath.Join(serveDataDir, "history.jsonl"))
	if err != nil {
		return err
	}
	engine.SetOnFinalize(histStore.Record)
	// Static demo indicators (always on, for testing); the live feed adds to these.
	engine.LoadThreats([]string{"malware.test", "c2.example.com"}, nil)

	// Restore the persisted audit log so events survive a restart.
	eventsPath := filepath.Join(serveDataDir, "events.json")
	if b, err := os.ReadFile(eventsPath); err == nil {
		var saved []detect.Event
		if json.Unmarshal(b, &saved) == nil {
			engine.RestoreEvents(saved)
			log.Printf("restored %d event(s) from %s", len(saved), eventsPath)
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
		loader := threatfeed.New(engine, feeds, serveThreatRefresh, log.Printf)
		go loader.Run(feedCtx)
	}

	rsStore, err := ruleset.NewStore(serveDataDir + "/rulesets.json")
	if err != nil {
		return err
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
	inbStore, err := inbound.NewStore(serveDataDir + "/inbound.json")
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

	mgr := gateway.NewManager(serveConfig, serveDataDir, wlStore.Get(), engine, secret)
	mgr.SetInitialMode(serveMode)
	mgr.SetInitialBlacklist(blStore.Get())
	mgr.SetInitialDirectList(dlStore.Get())
	mgr.SetInitialRuleSets(rsStore.Get())
	mgr.SetInitialDNS(dnsStore.Get())
	mgr.SetInitialInbound(inbStore.Get())
	mgr.SetInitialTUN(tunStore.Get())
	mgr.SetInitialEndpoints(epStore.All())
	mgr.SetInitialManagementPorts(managementPorts(serveMgmtPorts, serveAPIAddr))
	if err := mgr.Start(); err != nil {
		return err
	}
	defer mgr.Close()

	store, err := subscription.NewStore(serveDataDir + "/subscriptions.json")
	if err != nil {
		return err
	}
	apiSrv := api.NewServer(api.Options{
		Addr:        serveAPIAddr,
		Store:       store,
		Applier:     mgr,
		Whitelist:   wlStore,
		WLApplier:   mgr,
		Blacklist:   blStore,
		BLApplier:   mgr,
		Directlist:  dlStore,
		DLApplier:   mgr,
		Detect:      engine,
		Mode:        mgr,
		RuleSets:    rsStore,
		RSApplier:   mgr,
		Profiles:    profStore,
		ProfApplier: mgr,
		DNS:         dnsStore,
		DNSApplier:  mgr,
		Inbound:     inbStore,
		InbApplier:  mgr,
		TUN:         tunStore,
		TUNApplier:  mgr,
		Endpoints:   epStore,
		EPApplier:   mgr,
		History:     histStore,
		Nodes:       nodesStore,
		Token:       serveAPIToken,
		Clash:       clash.New(serveClashAddr, secret),
		ConsoleDir:  serveConsoleDir,
		ConsoleFS:   embeddedUI,
	})
	go func() {
		if err := apiSrv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Println("backend api:", err)
		}
	}()
	defer apiSrv.Close()

	log.Printf("trust-proxy serve: gateway up, backend API at http://%s", serveAPIAddr)
	log.Printf("dashboard: http://%s/", serveAPIAddr)
	log.Printf("mode: %s | auto-block: %v", mgr.Mode(), serveAutoBlock)

	// Persist the audit log periodically so a crash loses at most one interval.
	saveEvents := func() {
		if b, err := json.Marshal(engine.Events()); err == nil {
			_ = os.WriteFile(eventsPath, b, 0o600)
		}
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
	<-signals
	log.Println("shutting down")
	close(stopSave)
	saveEvents()
	return nil
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
