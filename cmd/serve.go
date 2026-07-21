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
)

var (
	serveConfig  string
	serveAPIAddr string
	serveDataDir string
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
}

func runServe() error {
	instance, _, err := gateway.Bootstrap(serveConfig)
	if err != nil {
		return err
	}
	if err = instance.Start(); err != nil {
		return err
	}
	defer instance.Close()

	store, err := subscription.NewStore(serveDataDir + "/subscriptions.json")
	if err != nil {
		return err
	}
	apiSrv := api.NewServer(serveAPIAddr, store)
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
