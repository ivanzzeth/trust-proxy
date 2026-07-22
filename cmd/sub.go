package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/pkg/client"
)

var apiAddr string

var subCmd = &cobra.Command{
	Use:   "sub",
	Short: "Manage subscriptions (CLI client -> backend API via SDK)",
}

var subLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List subscriptions",
	RunE: func(cmd *cobra.Command, args []string) error {
		subs, err := sdk().ListSubscriptions()
		if err != nil {
			return err
		}
		if len(subs) == 0 {
			fmt.Println("(no subscriptions)")
			return nil
		}
		fmt.Printf("%-14s %-20s %-6s %s\n", "ID", "NAME", "NODES", "URL")
		for _, s := range subs {
			name := s.Name
			if name == "" {
				name = "-"
			}
			fmt.Printf("%-14s %-20s %-6d %s\n", s.ID, name, s.NodeCount, s.URL)
			if s.LastError != "" {
				fmt.Printf("   ! last error: %s\n", s.LastError)
			}
		}
		return nil
	},
}

var (
	subAddName string
	subAddUA   string
	subAddVia  string
)

var subAddCmd = &cobra.Command{
	Use:   "add <url>",
	Short: "Add (and fetch) a subscription",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := sdk().AddSubscription(subAddName, args[0], subAddUA, subAddVia)
		if err != nil {
			return err
		}
		fmt.Printf("added %s (%s): %d nodes\n", s.ID, s.Name, s.NodeCount)
		if s.LastError != "" {
			fmt.Printf("   ! last error: %s\n", s.LastError)
		}
		return nil
	},
}

var subImportName string

var subImportCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Add nodes manually from pasted text / a file / stdin (no fetch)",
	Long:  "Read node text (share links, base64, Clash YAML or sing-box JSON) from a file argument or stdin and add it as a manual subscription.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			content []byte
			err     error
		)
		if len(args) == 1 {
			content, err = os.ReadFile(args[0])
		} else {
			content, err = io.ReadAll(os.Stdin)
		}
		if err != nil {
			return err
		}
		s, err := sdk().ImportNodes(subImportName, string(content))
		if err != nil {
			return err
		}
		fmt.Printf("imported %s (%s): %d nodes\n", s.ID, s.Name, s.NodeCount)
		return nil
	},
}

var subApplyCmd = &cobra.Command{
	Use:   "apply <id>",
	Short: "Apply a subscription's nodes to the running gateway (hot reload)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := sdk().ApplySubscription(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("applied %s (%s): %d nodes now live in the `proxy` group\n", s.ID, s.Name, s.NodeCount)
		return nil
	},
}

var subRmCmd = &cobra.Command{
	Use:   "rm <id>",
	Short: "Remove a subscription",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().DeleteSubscription(args[0]); err != nil {
			return err
		}
		fmt.Println("removed", args[0])
		return nil
	},
}

var subRefreshCmd = &cobra.Command{
	Use:   "refresh <id>",
	Short: "Re-fetch and re-parse a subscription",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := sdk().RefreshSubscription(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("refreshed %s: %d nodes\n", s.ID, s.NodeCount)
		return nil
	},
}

func init() {
	subCmd.PersistentFlags().StringVar(&apiAddr, "api-addr", "127.0.0.1:9096", "backend API address")
	subAddCmd.Flags().StringVar(&subAddName, "name", "", "friendly name")
	subAddCmd.Flags().StringVar(&subAddUA, "ua", "", "User-Agent for fetching (default: clash-verge/v2.0.0)")
	subAddCmd.Flags().StringVar(&subAddVia, "via", "", "fetch through a proxy (socks5://host:port or http://host:port)")
	subImportCmd.Flags().StringVar(&subImportName, "name", "", "friendly name")
	subCmd.AddCommand(subLsCmd, subAddCmd, subImportCmd, subApplyCmd, subRmCmd, subRefreshCmd)
}

func sdk() *client.Client {
	return client.New(client.Options{APIBaseURL: apiAddr})
}
