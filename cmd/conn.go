package cmd

import (
	"fmt"

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
		snap, err := connSource()
		if err != nil {
			return err
		}
		if jsonOut {
			return emit(snap)
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
		if args[0] == "all" {
			// No API equivalent: closing everything is a Clash primitive and there is
			// no reason for the backend to own it.
			if err := clashClient().CloseAllConnections(); err != nil {
				return err
			}
			fmt.Println("closed all connections")
			return nil
		}
		if clashSecret != "" {
			if err := clashClient().CloseConnection(args[0]); err != nil {
				return err
			}
		} else if err := sdk().APIKillConnection(args[0]); err != nil {
			return err
		}
		fmt.Println("closed", args[0])
		return nil
	},
}

func init() {
	connCmd.PersistentFlags().StringVar(&clashAddr, "clash-addr", "127.0.0.1:21586", "Clash API address")
	connCmd.PersistentFlags().StringVar(&clashSecret, "clash-secret", "",
		"talk to a Clash API directly with this secret, instead of going through the gateway's own API")
	connCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "print the raw JSON response instead of a table")
	connCmd.AddCommand(connLsCmd, connKillCmd)
}

// connSource reads the live connections.
//
// Through the backend by default. This used to build a raw Clash client and hunt for
// the secret in "data/clash-secret" — a *relative* path, so it only ever worked from
// inside a checkout that happened to have a data directory; on a real install it
// found nothing, sent no secret, and got 401. Which is the mistake this project
// already fixed once for -c, whose default was a repo-relative
// configs/config.json.
//
// Using the correct absolute path would not have fixed it: the data directory is
// root-owned and 0700, so an unprivileged CLI cannot read that secret, deliberately
// — the same reason the browser never sees it. The backend already proxies Clash and
// scopes the answer to the caller.
//
// --clash-secret still talks to a Clash instance directly, which is the point of
// pkg/clash: it works against any sing-box, mihomo or clash, ours included.
func connSource() (clash.Connections, error) {
	if clashSecret != "" {
		return clashClient().Connections()
	}
	return sdk().APIConnections()
}

func clashClient() *clash.Client {
	return clash.New(clashAddr, clashSecret)
}
