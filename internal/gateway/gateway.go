// Package gateway boots and owns the embedded sing-box instance (the data
// plane) and attaches our detection tracker to its router.
package gateway

import (
	"context"
	"os"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// Bootstrap builds (but does not start) a sing-box instance from a JSON config,
// with our detection tracker attached to the router. Mirrors the sing-box CLI
// so we track its extended-JSON config schema.
func Bootstrap(configPath string) (*box.Box, log.Logger, error) {
	logger := log.StdLogger()

	ctx := service.ContextWith(context.Background(), deprecated.NewStderrManager(logger))
	ctx = include.Context(ctx)

	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, err
	}

	options, err := json.UnmarshalExtendedContext[option.Options](ctx, content)
	if err != nil {
		return nil, nil, err
	}

	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return nil, nil, err
	}

	// Attach the detection engine to the data path. Must happen before Start().
	instance.Router().AppendTracker(newDetector(logger))

	return instance, logger, nil
}
