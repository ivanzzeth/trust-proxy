package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/pkg/clash"
)

var (
	clashAddr   string
	clashSecret string
)

// connCmd groups the low-level standard Clash primitives (connections).
var connCmd = &cobra.Command{
	Use:   "conn",
	Short: "Inspect / kill live connections (low-level Clash API primitives)",
}

var connLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List active connections",
	RunE: func(cmd *cobra.Command, args []string) error {
		snap, err := clashClient().Connections()
		if err != nil {
			return err
		}
		fmt.Printf("total up=%d down=%d, %d active\n", snap.UploadTotal, snap.DownloadTotal, len(snap.Connections))
		fmt.Printf("%-36s %-5s %-28s %-9s %-9s %s\n", "ID", "NET", "HOST", "UP", "DOWN", "RULE")
		for _, c := range snap.Connections {
			host := c.Metadata.Host
			if host == "" {
				host = c.Metadata.DestinationIP + ":" + c.Metadata.DestinationPort
			}
			fmt.Printf("%-36s %-5s %-28s %-9d %-9d %s\n", c.ID, c.Metadata.Network, host, c.Upload, c.Download, c.Rule)
		}
		return nil
	},
}

var connKillCmd = &cobra.Command{
	Use:   "kill <id|all>",
	Short: "Close a connection by id, or all",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := clashClient()
		if args[0] == "all" {
			if err := c.CloseAllConnections(); err != nil {
				return err
			}
			fmt.Println("closed all connections")
			return nil
		}
		if err := c.CloseConnection(args[0]); err != nil {
			return err
		}
		fmt.Println("closed", args[0])
		return nil
	},
}

func init() {
	connCmd.PersistentFlags().StringVar(&clashAddr, "clash-addr", "127.0.0.1:9090", "Clash API address")
	connCmd.PersistentFlags().StringVar(&clashSecret, "clash-secret", "", "Clash API secret (empty = read data/clash-secret)")
	connCmd.AddCommand(connLsCmd, connKillCmd)
}

func clashClient() *clash.Client {
	secret := clashSecret
	if secret == "" {
		if b, err := os.ReadFile("data/clash-secret"); err == nil {
			secret = strings.TrimSpace(string(b))
		}
	}
	return clash.New(clashAddr, secret)
}
