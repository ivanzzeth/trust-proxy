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
	// serve/proxy run the gateway or an exit node; everything else is a CLI
	// client for a running backend and shares --api-addr/--api-token/--json.
	clients := []*cobra.Command{
		subCmd, aclCmd, rulesCmd, statusCmd, modeCmd, routingCmd, postureCmd, finalCmd,
		dnsCmd, tunCmd, groupsCmd, endpointsCmd, proxiesCmd, autoBlockCmd,
		profileCmd, detectionsCmd, historyCmd, nodeCmd, detectCmd, quarantineCmd, netcheckCmd,
		authCmd, apikeyCmd, userCmd, requestCmd,
	}
	addClientFlags(clients...)
	rootCmd.AddCommand(append(clients, serveCmd, connCmd, proxyCmd, serviceCmd, selftestCmd)...)
}
