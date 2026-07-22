package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/api"
	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/gateway"
	"github.com/ivanzzeth/trust-proxy/internal/subscription"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/clash"
)

var (
	serveConfig      string
	serveAPIAddr     string
	serveDataDir     string
	serveConsoleDir  string
	serveClashAddr   string
	serveClashSecret string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the gateway: sing-box data plane + detection + backend API",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runServe()
	},
}

func init() {
	f := serveCmd.Flags()
	f.StringVarP(&serveConfig, "config", "c", "configs/config.json", "sing-box config path")
	f.StringVar(&serveAPIAddr, "api-addr", "127.0.0.1:9096", "trust-proxy backend API listen address")
	f.StringVar(&serveDataDir, "data", "data", "data directory (subscriptions, etc.)")
	f.StringVar(&serveConsoleDir, "console", "console/public", "React console static dir (Yacd build output)")
	f.StringVar(&serveClashAddr, "clash-addr", "127.0.0.1:9090", "Clash API address (proxied to the console)")
	f.StringVar(&serveClashSecret, "clash-secret", "", "Clash API secret (empty = load/generate a random one in the data dir)")
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

	engine := detect.New(2000)
	// Demo threat indicators; replace/extend with a real feed (abuse.ch, etc.).
	engine.LoadThreats([]string{"malware.test", "c2.example.com"}, nil)

	mgr := gateway.NewManager(serveConfig, wlStore.Get(), engine, secret)
	if err := mgr.Start(); err != nil {
		return err
	}
	defer mgr.Close()

	store, err := subscription.NewStore(serveDataDir + "/subscriptions.json")
	if err != nil {
		return err
	}
	apiSrv := api.NewServer(api.Options{
		Addr:       serveAPIAddr,
		Store:      store,
		Applier:    mgr,
		Whitelist:  wlStore,
		WLApplier:  mgr,
		Detect:     engine,
		Clash:      clash.New(serveClashAddr, secret),
		ConsoleDir: serveConsoleDir,
	})
	go func() {
		if err := apiSrv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Println("backend api:", err)
		}
	}()
	defer apiSrv.Close()

	log.Printf("trust-proxy serve: gateway up, backend API at http://%s", serveAPIAddr)
	host, port, _ := strings.Cut(serveClashAddr, ":")
	if host == "" {
		host = "127.0.0.1"
	}
	log.Printf("console: http://%s/?hostname=%s&port=%s&secret=%s", serveAPIAddr, host, port, secret)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals
	log.Println("shutting down")
	return nil
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
