//go:build embed_ui

// Build with -tags embed_ui to bake the dashboard build (dashboard/dist) into
// the binary, so `trust-proxy serve` needs no on-disk UI. Requires the
// dashboard to be built first (make dashboard). Default builds omit this and
// serve the dashboard from disk.
package main

import (
	"embed"
	"io/fs"

	"github.com/ivanzzeth/trust-proxy/cmd"
)

//go:embed all:dashboard/dist
var dashboardFS embed.FS

func init() {
	if sub, err := fs.Sub(dashboardFS, "dashboard/dist"); err == nil {
		cmd.SetEmbeddedUI(sub)
	}
}
