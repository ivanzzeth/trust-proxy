package cmd

import "github.com/spf13/cobra"

// version is injected at build time via -ldflags "-X .../cmd.version=<tag>".
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "trust-proxy",
	Short: "Egress control / detection gateway built on sing-box",
	Long: "trust-proxy is one binary. `install` puts the gateway on this machine as a\n" +
		"system service — root, machine-wide, started at boot — and claims it for you.\n" +
		"Everything else is a CLI client that talks to that gateway through the Go SDK.\n\n" +
		"    sudo trust-proxy install      # the whole setup, once\n" +
		"    trust-proxy status            # what it is doing\n" +
		"    sudo trust-proxy uninstall    # the escape hatch",
	Version:       version,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command.
func Execute() error {
	// One place decorates authentication failures, so every subcommand gets the
	// same actionable message instead of each remembering to.
	return decorateAuthError(rootCmd.Execute(), resolveToken())
}

func init() {
	// serve/proxy run the gateway or an exit node; everything else is a CLI
	// client for a running backend and shares --api-addr/--api-token/--json.
	clients := []*cobra.Command{
		subCmd, aclCmd, rulesCmd, statusCmd, modeCmd, routingCmd, postureCmd, finalCmd,
		dnsCmd, tunCmd, groupsCmd, endpointsCmd, proxiesCmd, autoBlockCmd,
		profileCmd, detectionsCmd, historyCmd, nodeCmd, detectCmd, quarantineCmd, netcheckCmd,
		authCmd, apikeyCmd, userCmd, requestCmd, envCmd,
	}
	addClientFlags(clients...)
	// install/uninstall are local, privileged and machine-shaped: they deliberately
	// take no --api-addr pointing elsewhere, because they have to work when no
	// gateway is running at all.
	local := []*cobra.Command{
		newInstallCmd(false), newUninstallCmd(false),
		serveCmd, connCmd, proxyCmd, serviceCmd, selftestCmd, versionCmd,
	}
	rootCmd.AddCommand(append(clients, local...)...)
	versionCmd.Flags().BoolVar(&jsonOut, "json", false, "print the raw JSON response instead of a table")
}
