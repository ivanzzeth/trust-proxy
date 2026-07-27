package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// `version` answers what a *binary* is, as opposed to `status`, which asks a
// running gateway what it is doing.
//
// The one field worth having beyond the version string is `console`: a build
// without the UI embedded looks identical from the outside and only reveals
// itself as a page saying "dashboard not built" — after it has been installed as
// a service. Anything that ships a binary (the app bundle, `service install`)
// should be able to ask rather than grep the executable for a marker string.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version and what this build includes",
	RunE: func(cmd *cobra.Command, args []string) error {
		return out(map[string]any{
			"version": version,
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
			"console": embeddedUI != nil,
		}, func() {
			fmt.Printf("%-9s %s\n", "version:", version)
			fmt.Printf("%-9s %s/%s\n", "platform:", runtime.GOOS, runtime.GOARCH)
			if embeddedUI != nil {
				fmt.Printf("%-9s embedded\n", "console:")
			} else {
				// Not an error — a headless gateway is a legitimate build — but it
				// is the difference between an install that works and one that
				// serves a blank page, so it does not get to be implicit.
				fmt.Printf("%-9s none (built without -tags embed_ui; `service install` will refuse it)\n", "console:")
			}
		})
	},
}
