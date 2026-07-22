package cmd

import "github.com/spf13/cobra"

// version is injected at build time via -ldflags "-X .../cmd.version=<tag>".
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "trust-proxy",
	Short: "Egress control / detection gateway built on sing-box",
	Long: "trust-proxy is one binary: `serve` runs the gateway (sing-box + detection + API);\n" +
		"other subcommands are a CLI client that talks to a running backend via the Go SDK.",
	Version:       version,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(serveCmd, subCmd, connCmd, proxyCmd)
}
