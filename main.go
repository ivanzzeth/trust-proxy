// Command trust-proxy boots an embedded sing-box instance from a JSON config.
//
// Milestone 0: just get the full stack running.
//   - imports sing-box as a library (pinned via the third_party/sing-box submodule)
//   - loads configs/config.json using sing-box's own extended-JSON parser
//   - the config enables the built-in API service (service/api) + dashboard,
//     which the cloned official React UI (webui/) talks to over Connect/protobuf
//
// Later milestones layer our own detection/enforcement on top via
// route.Router.AppendTracker (see docs) and our own /api endpoints.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func main() {
	configPath := flag.String("c", "configs/config.json", "path to sing-box config JSON")
	flag.Parse()

	logger := log.StdLogger()

	if err := run(*configPath, logger); err != nil {
		logger.Fatal(err)
	}
}

func run(configPath string, logger log.Logger) error {
	// Build the context the same way the sing-box CLI does: register the
	// deprecated-field manager, then all built-in inbound/outbound/dns/service
	// registries via include.Context. This is what makes the extended JSON
	// parser and box.New able to resolve every "type" in the config.
	ctx := service.ContextWith(context.Background(), deprecated.NewStderrManager(logger))
	ctx = include.Context(ctx)

	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	options, err := json.UnmarshalExtendedContext[option.Options](ctx, content)
	if err != nil {
		return err
	}

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return err
	}

	// Attach our detection engine to the data path. AppendTracker must be
	// called before connections start flowing, i.e. before Start().
	instance.Router().AppendTracker(newDetector(logger))

	if err = instance.Start(); err != nil {
		return err
	}
	logger.Info("trust-proxy started")

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals

	logger.Info("shutting down")
	return instance.Close()
}
