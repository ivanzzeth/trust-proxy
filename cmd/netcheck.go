package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// netcheckCmd shows the host-level picture the gateway watches for bypasses it
// would otherwise never see: a rogue DHCP route steering traffic around the
// tunnel (TunnelVision), or a network claiming public space is "local"
// (TunnelCrack LocalNet). Observation only — nothing here changes the system.
var netcheckCmd = &cobra.Command{
	Use:   "netcheck",
	Short: "Host routing / interface state the gateway watches for tunnel bypasses",
	RunE: func(cmd *cobra.Command, args []string) error {
		snap, err := sdk().NetworkState()
		if err != nil {
			return err
		}
		return out(snap, func() {
			fmt.Printf("supported:     %v\n", snap["supported"])
			fmt.Printf("tunnel ifaces: %v\n", snap["tun_ifaces"])
			fmt.Printf("default via:   %v\n", dash(str(snap["default_via"])))
			fmt.Printf("local subnets: %v\n", snap["local_nets"])
			if routes, ok := snap["routes"].([]any); ok {
				fmt.Printf("routes:        %d (of which %v are host routes — one per direct dial, not reported)\n",
					len(routes), snap["host_routes"])
			}
			fmt.Println()
			fmt.Println("A destination inside the LAN bypass (RFC1918 / CGNAT) but outside the")
			fmt.Println("subnets above is reported as a LocalNet finding; new non-tunnel routes")
			fmt.Println("covering public space are reported as route-hijack. See `detections ls`.")
		})
	},
}

func init() { netcheckCmd.SilenceUsage = true }
