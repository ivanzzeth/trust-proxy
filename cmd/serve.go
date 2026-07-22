package cmd

import (
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/api"
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
	f.StringVar(&serveClashSecret, "clash-secret", "trust-proxy", "Clash API secret")
}

func runServe() error {
	wlStore, err := whitelist.NewStore(serveDataDir + "/whitelist.json")
	if err != nil {
		return err
	}

	mgr := gateway.NewManager(serveConfig, wlStore.Get())
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
		Clash:      clash.New(serveClashAddr, serveClashSecret),
		ConsoleDir: serveConsoleDir,
	})
	go func() {
		if err := apiSrv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Println("backend api:", err)
		}
	}()
	defer apiSrv.Close()

	log.Printf("trust-proxy serve: gateway up, backend API at http://%s", serveAPIAddr)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals
	log.Println("shutting down")
	return nil
}
