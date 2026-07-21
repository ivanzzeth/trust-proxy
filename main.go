// Command trust-proxy is a single binary that is both the gateway backend and
// its CLI client. `trust-proxy serve` runs the gateway (sing-box data plane +
// detection + our own API); every other subcommand is a client that talks to a
// running backend through the Go SDK (pkg/clash for standard Clash primitives,
// pkg/client for the higher-level trust-proxy API).
package main

import (
	"fmt"
	"os"

	"github.com/ivanzzeth/trust-proxy/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
