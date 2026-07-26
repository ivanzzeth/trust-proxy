// Command trust-proxy is a single binary that is both the gateway backend and
// its CLI client. `trust-proxy serve` runs the gateway (sing-box data plane +
// detection + our own API); every other subcommand is a client that talks to a
// running backend through the Go SDK (pkg/clash for standard Clash primitives,
// pkg/client for the higher-level trust-proxy API).
package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/ivanzzeth/trust-proxy/cmd"
)

// The shipped gateway config, compiled in so `serve` can seed a fresh data
// directory without a checkout on disk. Embedding lives here because go:embed
// cannot reach outside its own package directory, and this is the only package
// above configs/ — so the repo keeps exactly one copy of the file.
//
//go:embed configs/config.json
var defaultConfig []byte

func main() {
	cmd.SetDefaultConfig(defaultConfig)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
