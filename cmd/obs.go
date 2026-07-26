package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// Observability + snapshots + fleet: the read-mostly half of the API.

// ---- profiles ------------------------------------------------------------

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Named policy snapshots (one-click switching)",
}

var profileLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List profiles",
	RunE: func(cmd *cobra.Command, args []string) error {
		profs, err := sdk().Profiles()
		if err != nil {
			return err
		}
		return out(profs, func() {
			if len(profs) == 0 {
				fmt.Println("(no profiles)")
				return
			}
			fmt.Printf("%-14s %-24s %-8s %-8s %s\n", "ID", "NAME", "MODE", "RULES", "SETS")
			for _, p := range profs {
				fmt.Printf("%-14s %-24s %-8s %-8d %d\n",
					p.ID, truncate(p.Name, 24), dash(p.Mode), len(p.CustomRules), len(p.RuleSets))
			}
		})
	},
}

var profileSaveCmd = &cobra.Command{
	Use:   "save <name>",
	Short: "Snapshot the current policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := sdk().SaveProfile(args[0])
		if err != nil {
			return err
		}
		return out(p, func() { fmt.Printf("saved %s (%s)\n", p.ID, p.Name) })
	},
}

var profileActivateCmd = &cobra.Command{
	Use:   "activate <id>",
	Short: "Apply a snapshot (one atomic rebuild)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := sdk().ActivateProfile(args[0])
		if err != nil {
			return err
		}
		return out(p, func() { fmt.Printf("activated %s (%s), mode=%s\n", p.ID, p.Name, dash(p.Mode)) })
	},
}

var profileRmCmd = &cobra.Command{
	Use:   "rm <id>",
	Short: "Delete a snapshot",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().DeleteProfile(args[0]); err != nil {
			return err
		}
		fmt.Println("removed", args[0])
		return nil
	},
}

// ---- detections ----------------------------------------------------------

var (
	detKind  string
	detQuery string
	detLimit int
)

var detectionsCmd = &cobra.Command{
	Use:   "detections",
	Short: "Detection events (threat hits, beaconing, DGA/tunnel, large uploads)",
}

var detectionsLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List detection events, newest first",
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := sdk().Detections(detKind, detQuery, detLimit)
		if err != nil {
			return err
		}
		if jsonOut {
			return emit(res)
		}
		items, _ := res["items"].([]any)
		if len(items) == 0 {
			fmt.Println("(no detections)")
			return nil
		}
		fmt.Printf("%-22s %-16s %-34s %-7s %s\n", "TIME", "KIND", "HOST", "BLOCK", "DETAIL")
		for _, it := range items {
			m, _ := it.(map[string]any)
			fmt.Printf("%-22s %-16s %-34s %-7v %s\n",
				truncate(str(m["time"]), 22), truncate(str(m["kind"]), 16), truncate(str(m["host"]), 34),
				m["block"], truncate(str(m["detail"]), 40))
		}
		return nil
	},
}

var detectionsStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Detection counters",
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := sdk().DetectionStats()
		if err != nil {
			return err
		}
		return out(res, func() {
			for _, k := range sortedKeys(res) {
				fmt.Printf("%-18s %v\n", k+":", res[k])
			}
		})
	},
}

// ---- history -------------------------------------------------------------

var (
	histQuery string
	histLimit int
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Per-connection history (persisted; survives restarts)",
}

var historyLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List completed connections, newest first",
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := sdk().History(histQuery, histLimit)
		if err != nil {
			return err
		}
		if jsonOut {
			return emit(res)
		}
		items, _ := res["items"].([]any)
		if len(items) == 0 {
			fmt.Println("(no history)")
			return nil
		}
		fmt.Printf("%-22s %-34s %-12s %-12s %s\n", "CLOSED", "HOST", "UP", "DOWN", "OUTBOUND")
		for _, it := range items {
			m, _ := it.(map[string]any)
			fmt.Printf("%-22s %-34s %-12v %-12v %s\n",
				truncate(str(m["closed_at"]), 22), truncate(str(m["host"]), 34),
				m["upload"], m["download"], truncate(str(m["outbound"]), 20))
		}
		return nil
	},
}

var historyStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Top talkers + 24h trend",
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := sdk().HistoryStats()
		if err != nil {
			return err
		}
		if jsonOut {
			return emit(res)
		}
		talkers, _ := res["top_talkers"].([]any)
		if len(talkers) == 0 {
			fmt.Println("(no traffic recorded yet)")
			return nil
		}
		fmt.Printf("%-40s %-12s %-12s %s\n", "HOST", "UP", "DOWN", "CONNS")
		for _, t := range talkers {
			m, _ := t.(map[string]any)
			// JSON numbers decode to float64: printing them raw gave "5.426577e+06".
			fmt.Printf("%-40s %-12s %-12s %v\n",
				truncate(str(m["host"]), 40), humanBytes(asInt64(m["up"])), humanBytes(asInt64(m["down"])), m["count"])
		}
		return nil
	},
}

// ---- fleet ---------------------------------------------------------------

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Registered gateways: administer them, or use one as this machine's exit",
}

var (
	nodeExitHost string
	nodeExitPort int
	nodeExitUser string
	nodeExitPass string
	nodeMode     string
)

// `node exit` is the CLI half of "use that gateway as my exit": it becomes a
// socks outbound in the proxy group, so afterwards `proxies select` picks it like
// any other node.
var nodeExitCmd = &cobra.Command{
	Use:   "exit <id|name>",
	Short: "Use a registered gateway as this machine's exit (--off to stop)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := resolveGateway(args[0])
		if err != nil {
			return err
		}
		req := map[string]any{"as_exit": !nodeExitOff}
		if nodeExitHost != "" {
			req["proxy_host"] = nodeExitHost
		}
		if nodeExitPort > 0 {
			req["proxy_port"] = nodeExitPort
		}
		if nodeExitUser != "" {
			req["proxy_user"] = nodeExitUser
		}
		if nodeExitPass != "" {
			req["proxy_pass"] = nodeExitPass
		}
		n, err := sdk().PatchNode(id, req)
		if err != nil {
			return err
		}
		return out(n, func() {
			if nodeExitOff {
				fmt.Printf("✓ %s is no longer an exit\n", str(n["name"]))
				return
			}
			fmt.Printf("✓ %s is now an exit (%s:%v as %s)\n  select it with: trust-proxy proxies select proxy gw-%s\n",
				str(n["name"]), str(n["proxy_host"]), n["proxy_port"], str(n["proxy_user"]), str(n["name"]))
		})
	},
}

var nodeExitOff bool

var nodeToggleCmd = &cobra.Command{
	Use:   "toggle <id|name>",
	Short: "Enable or disable a gateway entry (--off to disable)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := resolveGateway(args[0])
		if err != nil {
			return err
		}
		n, err := sdk().PatchNode(id, map[string]any{"enabled": !nodeExitOff})
		if err != nil {
			return err
		}
		return out(n, func() { fmt.Printf("✓ %s enabled=%v\n", str(n["name"]), n["enabled"]) })
	},
}

var nodeModeCmd = &cobra.Command{
	Use:   "mode <gateway|client>",
	Short: "Is this machine a gateway (runs a data plane) or a client (console only)?",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		n, err := sdk().PatchNode("local", map[string]any{"mode": args[0]})
		if err != nil {
			return err
		}
		return out(n, func() { fmt.Printf("✓ this machine is now in %s mode\n", str(n["mode"])) })
	},
}

// resolveGateway accepts an id or a name.
func resolveGateway(ref string) (string, error) {
	list, err := sdk().Nodes()
	if err != nil {
		return "", err
	}
	for _, n := range list {
		if str(n["id"]) == ref || strings.EqualFold(str(n["name"]), ref) {
			return str(n["id"]), nil
		}
	}
	return "", fmt.Errorf("no such gateway %q", ref)
}

var nodeLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List gateways (including this machine)",
	RunE: func(cmd *cobra.Command, args []string) error {
		nodes, err := sdk().Nodes()
		if err != nil {
			return err
		}
		return out(nodes, func() {
			if len(nodes) == 0 {
				fmt.Println("(no probes registered)")
				return
			}
			fmt.Printf("%-14s %-20s %s\n", "ID", "NAME", "URL")
			for _, n := range nodes {
				fmt.Printf("%-14s %-20s %s\n", str(n["id"]), truncate(str(n["name"]), 20), str(n["url"]))
			}
		})
	},
}

var nodeToken string

var nodeAddCmd = &cobra.Command{
	Use:   "add <name> <api-url>",
	Short: "Register a probe (its /api URL; --token for its bearer)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		n, err := sdk().AddNode(args[0], args[1], nodeToken)
		if err != nil {
			return err
		}
		return out(n, func() { fmt.Printf("registered %s (%s)\n", str(n["id"]), args[0]) })
	},
}

var nodeRmCmd = &cobra.Command{
	Use:   "rm <id>",
	Short: "Unregister a probe",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().DeleteNode(args[0]); err != nil {
			return err
		}
		fmt.Println("removed", args[0])
		return nil
	},
}

// asInt64 converts a JSON-decoded number to int64.
func asInt64(v any) int64 {
	f, _ := v.(float64)
	return int64(f)
}

// str renders a JSON-decoded value for a table cell.
func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func init() {
	detectionsLsCmd.Flags().StringVar(&detKind, "kind", "", "filter by kind (threat|beacon|dga|tunnel|upload…)")
	detectionsLsCmd.Flags().StringVar(&detQuery, "q", "", "substring filter on host/detail")
	detectionsLsCmd.Flags().IntVar(&detLimit, "limit", 50, "max events")
	historyLsCmd.Flags().StringVar(&histQuery, "q", "", "substring filter on host")
	historyLsCmd.Flags().IntVar(&histLimit, "limit", 50, "max rows")
	nodeAddCmd.Flags().StringVar(&nodeToken, "token", "", "bearer token the probe requires")

	profileCmd.AddCommand(profileLsCmd, profileSaveCmd, profileActivateCmd, profileRmCmd)
	detectionsCmd.AddCommand(detectionsLsCmd, detectionsStatsCmd)
	historyCmd.AddCommand(historyLsCmd, historyStatsCmd)
	f := nodeExitCmd.Flags()
	f.StringVar(&nodeExitHost, "host", "", "proxy host to dial (default: the gateway URL's host)")
	f.IntVar(&nodeExitPort, "port", 0, "proxy port on that gateway (its mixed inbound, default 21584)")
	f.StringVar(&nodeExitUser, "user", "", "your account on that gateway")
	f.StringVar(&nodeExitPass, "password", "", "that account's proxy password")
	f.BoolVar(&nodeExitOff, "off", false, "stop using it as an exit")
	nodeToggleCmd.Flags().BoolVar(&nodeExitOff, "off", false, "disable instead of enable")
	nodeCmd.AddCommand(nodeLsCmd, nodeAddCmd, nodeRmCmd, nodeExitCmd, nodeToggleCmd, nodeModeCmd)
}
