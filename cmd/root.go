package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "trust-proxy",
	Short: "Egress control / detection gateway built on sing-box",
	Long: "trust-proxy is one binary: `serve` runs the gateway (sing-box + detection + API);\n" +
		"other subcommands are a CLI client that talks to a running backend via the Go SDK.",
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
