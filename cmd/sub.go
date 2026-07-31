package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/shellquote"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
	"github.com/ivanzzeth/trust-proxy/pkg/client"
)

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
		return out(subs, func() {
			if len(subs) == 0 {
				fmt.Println("(no subscriptions)")
				return
			}
			fmt.Printf("%-14s %-20s %-6s %-8s %s\n", "ID", "NAME", "NODES", "APPLIED", "URL")
			for _, s := range subs {
				name := s.Name
				if name == "" {
					name = "-"
				}
				fmt.Printf("%-14s %-20s %-6d %-8s %s\n", s.ID, name, s.NodeCount, yesNo(s.Applied), s.Source)
				if s.LastError != "" {
					fmt.Printf("   ! last error: %s\n", s.LastError)
				}
			}
		})
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

var subExportURLOnly bool

var subExportCmd = &cobra.Command{
	Use:   "export <id>",
	Short: "Print a subscription's origin so it can be recreated on another gateway",
	Long: "Reveal one subscription's URL (or pasted content) plus the user agent and via proxy used to fetch it.\n" +
		"`sub ls` deliberately masks the URL — it is an airport account — so this is the explicit way to ask for it.\n" +
		"Node credentials (uuid / password / reality keys) are never included: the target gateway re-fetches them.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := sdk().ExportSubscription(args[0])
		if err != nil {
			return err
		}
		if subExportURLOnly {
			if s.URL == "" {
				return fmt.Errorf("subscription %s was pasted, not fetched — it has no URL (use --json for its content)", s.ID)
			}
			fmt.Println(s.URL)
			return nil
		}
		return out(s, func() { fmt.Print(renderSubExport(s)) })
	},
}

// renderSubExport prints the origin and the command that recreates it elsewhere.
//
// The hint is generated from the real flag names and shell-quoted: a subscription
// URL carries ? and &, which a bare paste would turn into a glob and a background
// job. Empty fields emit no flag at all — a stray `--ua ''` would override the
// server's default User-Agent with an empty string, and UA gating is exactly how
// airports refuse a fetch.
func renderSubExport(s apitypes.SubscriptionExport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "name:       %s\n", dash(s.Name))
	if s.URL != "" {
		fmt.Fprintf(&b, "url:        %s\n", s.URL)
	} else {
		fmt.Fprintf(&b, "url:        (pasted — %d bytes of node text, use --json to get it)\n", len(s.Content))
	}
	if s.UserAgent != "" {
		fmt.Fprintf(&b, "user_agent: %s\n", s.UserAgent)
	}
	if s.Via != "" {
		fmt.Fprintf(&b, "via:        %s\n", s.Via)
	}
	b.WriteString("\n# recreate it on the other gateway:\n")
	if s.URL == "" {
		fmt.Fprintf(&b, "trust-proxy sub import <file> --name %s\n", shellquote.Quote(s.Name))
		return b.String()
	}
	parts := []string{"trust-proxy", "sub", "add", shellquote.Quote(s.URL)}
	if s.Name != "" {
		parts = append(parts, "--name", shellquote.Quote(s.Name))
	}
	if s.UserAgent != "" {
		parts = append(parts, "--ua", shellquote.Quote(s.UserAgent))
	}
	if s.Via != "" {
		parts = append(parts, "--via", shellquote.Quote(s.Via))
	}
	b.WriteString(strings.Join(parts, " ") + "\n")
	return b.String()
}

var subApplyCmd = &cobra.Command{
	Use:   "apply <id>",
	Short: "Add a subscription's nodes to the live proxy group (merges with other applied)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := sdk().ApplySubscription(args[0])
		if err != nil {
			return err
		}
		return out(s, func() {
			fmt.Printf("applied %s (%s): %d nodes from this sub now merged into the `proxy` group\n", s.ID, s.Name, s.NodeCount)
		})
	},
}

var subUnapplyCmd = &cobra.Command{
	Use:   "unapply <id>",
	Short: "Remove a subscription from the live proxy group (others stay)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := sdk().UnapplySubscription(args[0])
		if err != nil {
			return err
		}
		return out(s, func() {
			fmt.Printf("unapplied %s (%s); remaining applied subscriptions stay live\n", s.ID, s.Name)
		})
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
	subAddCmd.Flags().StringVar(&subAddName, "name", "", "friendly name")
	subAddCmd.Flags().StringVar(&subAddUA, "ua", "", "User-Agent for fetching (default: clash-verge/v2.0.0)")
	subAddCmd.Flags().StringVar(&subAddVia, "via", "", "fetch through a proxy (socks5://host:port or http://host:port)")
	subImportCmd.Flags().StringVar(&subImportName, "name", "", "friendly name")
	subExportCmd.Flags().BoolVar(&subExportURLOnly, "url-only", false, "print just the URL, for $(…) in a script")
	subCmd.AddCommand(subLsCmd, subAddCmd, subImportCmd, subExportCmd, subApplyCmd, subUnapplyCmd, subRmCmd, subRefreshCmd)
}

// sdk builds the SDK client from the shared client flags (see cmd/cli.go).
func sdk() *client.Client {
	return client.New(client.Options{APIBaseURL: apiAddr, Token: resolveToken()})
}
