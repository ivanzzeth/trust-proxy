package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Runtime knobs: capture mode, routing mode, posture, catch-all egress, resolver,
// TUN options, proxy groups and VPN endpoints.

// readJSONArg loads a JSON document from a file, or from stdin when path is "-".
// Used by the set commands whose payload is a whole document (dns, tun, groups).
func readJSONArg(path string, v any) error {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// ---- status --------------------------------------------------------------

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the gateway's runtime status",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := sdk().Status()
		if err != nil {
			return err
		}
		return out(st, func() {
			for _, k := range sortedKeys(st) {
				fmt.Printf("%-18s %v\n", k+":", st[k])
			}
		})
	},
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// small maps; a plain insertion sort keeps the output stable without a dep
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// ---- capture mode --------------------------------------------------------

var modeCmd = &cobra.Command{
	Use:   "mode",
	Short: "Capture mode: manual | system | tun",
}

var modeGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the current capture mode (and any pending guarded revert)",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := sdk().Mode()
		if err != nil {
			return err
		}
		return out(m, func() {
			fmt.Printf("mode: %v\n", m["mode"])
			if rev, ok := m["pending_revert"]; ok {
				fmt.Printf("pending revert: %v\n", rev)
			}
		})
	},
}

var modeGuard int

var modeSetCmd = &cobra.Command{
	Use:       "set <manual|system|tun>",
	Short:     "Switch capture mode (guarded by default: auto-reverts unless confirmed)",
	Long:      "tun needs root and takes over all traffic. The guard is a dead-man's switch:\nif you lose connectivity and cannot run `mode confirm`, the old mode comes back.",
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"manual", "system", "tun"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] == "tun" {
			if err := confirm("tun mode captures ALL traffic on this machine and needs root. Continue?"); err != nil {
				return err
			}
		}
		res, err := sdk().SetMode(args[0], modeGuard)
		if err != nil {
			return err
		}
		return out(res, func() {
			fmt.Printf("mode -> %s\n", args[0])
			if modeGuard > 0 {
				fmt.Printf("guard armed: reverts in %ds unless you run `trust-proxy mode confirm`\n", modeGuard)
			}
		})
	},
}

var modeConfirmCmd = &cobra.Command{
	Use:   "confirm",
	Short: "Confirm the last guarded mode switch (cancels the pending revert)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().ConfirmMode(); err != nil {
			return err
		}
		fmt.Println("confirmed; no revert pending")
		return nil
	},
}

// ---- routing mode (Rule/Global) -----------------------------------------

var routingCmd = &cobra.Command{
	Use:   "routing",
	Short: "Routing mode: Rule (policy applies) | Global (everything via the proxy)",
}

var routingGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the routing mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := sdk().ClashMode()
		if err != nil {
			return err
		}
		return out(m, func() { fmt.Printf("routing: %v\n", m["mode"]) })
	},
}

var routingSetCmd = &cobra.Command{
	Use:       "set <Rule|Global>",
	Short:     "Switch routing mode without a rebuild",
	Long:      "Global sends everything unlisted through the proxy — default-deny stops applying,\nthough the security floor (deny lists, threat hits, process/device gates) still does.\nDirect is refused: it would bypass the gateway entirely.",
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"Rule", "Global"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.EqualFold(args[0], "Global") {
			if err := confirm("Global turns default-deny off for unlisted destinations. Continue?"); err != nil {
				return err
			}
		}
		m, err := sdk().SetClashMode(args[0])
		if err != nil {
			return err
		}
		return out(m, func() { fmt.Printf("routing -> %v\n", m["mode"]) })
	},
}

// ---- posture + final egress ---------------------------------------------

var postureCmd = &cobra.Command{
	Use:   "posture",
	Short: "Security posture: strict (default-deny) | split (default-allow)",
}

var postureGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the active posture",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := sdk().Posture()
		if err != nil {
			return err
		}
		return out(p, func() { fmt.Printf("posture: %v\n", p["active"]) })
	},
}

var postureSetCmd = &cobra.Command{
	Use:       "set <strict|split>",
	Short:     "Switch posture (each posture keeps its own policy slot)",
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"strict", "split"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if args[0] == "split" {
			if err := confirm("split drops the Permit gate: unlisted destinations may egress. Continue?"); err != nil {
				return err
			}
		}
		p, err := sdk().SetPosture(args[0])
		if err != nil {
			return err
		}
		return out(p, func() {
			fmt.Printf("posture -> %v\n", p["active"])
			// Split seeds the catalog's remote rule sets, and a machine that cannot
			// download them gets them switched off rather than a gateway that will
			// not start. Saying which ones, and why, is the difference between a
			// degraded policy and a mysterious one.
			if list, ok := p["unreachable_sets"].([]any); ok && len(list) > 0 {
				names := make([]string, 0, len(list))
				for _, v := range list {
					names = append(names, fmt.Sprint(v))
				}
				fmt.Printf("\n⚠ %d rule set(s) could not be downloaded from any source and are OFF:\n    %s\n",
					len(names), strings.Join(names, ", "))
				fmt.Printf("  They need either a working route to GitHub/jsdelivr or an exit node.\n")
				fmt.Printf("  Add a node, then:  trust-proxy rules sets toggle <tag>\n")
			}
		})
	},
}

var finalCmd = &cobra.Command{
	Use:   "final",
	Short: "Catch-all egress for permitted-but-unrouted traffic",
}

var finalGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the catch-all egress",
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := sdk().Final()
		if err != nil {
			return err
		}
		return out(f, func() { fmt.Printf("final: %s\n", f.Outbound) })
	},
}

var finalSetCmd = &cobra.Command{
	Use:   "set <proxy|direct|<node tag>>",
	Short: "Set the catch-all egress (never opens the Permit gate)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := sdk().SetFinal(args[0])
		if err != nil {
			return err
		}
		return out(f, func() { fmt.Printf("final -> %s\n", f.Outbound) })
	},
}

// ---- DNS -----------------------------------------------------------------

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Resolver policy (servers, split rules, direct-route resolver)",
}

var dnsGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the resolver policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		d, err := sdk().DNS()
		if err != nil {
			return err
		}
		return out(d, func() {
			fmt.Printf("final: %s   strategy: %s\n", dash(d.Final), dash(d.Strategy))
			fmt.Printf("direct-route resolver: %s (split %s)\n",
				dashDefault(d.DirectServer, "223.5.5.5"), enabledWord(!d.DisableDirectSplit))
			fmt.Printf("%-12s %-8s %-24s %s\n", "TAG", "TYPE", "SERVER", "DETOUR")
			for _, s := range d.Servers {
				fmt.Printf("%-12s %-8s %-24s %s\n", s.Tag, s.Type, dash(s.Server), dash(s.Detour))
			}
			for _, r := range d.Rules {
				fmt.Printf("rule -> %s: domain_suffix=%v rule_set=%v\n", r.Server, r.DomainSuffix, r.RuleSet)
			}
		})
	},
}

func dashDefault(s, def string) string {
	if s == "" {
		return def + " (default)"
	}
	return s
}

func enabledWord(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

var (
	dnsFile         string
	dnsDirectServer string
	dnsDisplitSet   bool
	dnsFinal        string
	dnsStrategy     string
)

var dnsQueriesTop int

var dnsQueriesCmd = &cobra.Command{
	Use:   "queries",
	Short: "Query-level activity: totals, NXDOMAIN share, busiest parents",
	Long: "What the resolver is being asked for. A DGA sweep is mostly NXDOMAIN and a\n" +
		"DNS tunnel encodes payload into names, so neither shows up as a connection —\n" +
		"this is the only view where they are visible.",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := sdk().DNSQueryStats(dnsQueriesTop)
		if err != nil {
			return err
		}
		return out(st, func() {
			total, _ := st["total"].(float64)
			nx, _ := st["nxdomain"].(float64)
			odd, _ := st["odd_type"].(float64)
			share := 0.0
			if total > 0 {
				share = nx / total * 100
			}
			fmt.Printf("queries: %.0f   nxdomain: %.0f (%.1f%%)   TXT/NULL/ANY: %.0f\n", total, nx, share, odd)
			if ech, _ := st["ech_answers"].(float64); ech > 0 {
				names, _ := st["ech_domains"].([]any)
				fmt.Printf("ECH configs seen: %.0f answer(s)", ech)
				if len(names) > 0 {
					fmt.Printf(" — %s", truncate(joinAny(names, ", "), 60))
				}
				fmt.Println("  (these destinations' SNI is no longer visible to the Permit gate)")
			}
			parents, _ := st["top_parents"].([]any)
			if len(parents) == 0 {
				fmt.Println("(no query activity yet — the resolver sees queries only in TUN mode or when clients use our DNS)")
				return
			}
			fmt.Printf("%-44s %-10s %s\n", "PARENT", "QUERIES", "NXDOMAIN")
			for _, p := range parents {
				m, _ := p.(map[string]any)
				q, _ := m["queries"].(float64)
				n, _ := m["nxdomain"].(float64)
				fmt.Printf("%-44s %-10.0f %.0f\n", truncate(str(m["parent"]), 44), q, n)
			}
		})
	},
}

var dnsSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Update the resolver policy (whole doc with -f, or patch single knobs)",
	Long: "With -f the document replaces the policy wholesale. Without it the current\n" +
		"policy is fetched and only the flags you passed are changed — so you can flip\n" +
		"the direct-route resolver without restating every server.",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := sdk()
		var cfg apitypes.DNSConfig
		if dnsFile != "" {
			if err := readJSONArg(dnsFile, &cfg); err != nil {
				return err
			}
		} else {
			cur, err := c.DNS()
			if err != nil {
				return err
			}
			cfg = cur
			if cmd.Flags().Changed("direct-server") {
				cfg.DirectServer = dnsDirectServer
			}
			if cmd.Flags().Changed("disable-direct-split") {
				cfg.DisableDirectSplit = dnsDisplitSet
			}
			if cmd.Flags().Changed("final") {
				cfg.Final = dnsFinal
			}
			if cmd.Flags().Changed("strategy") {
				cfg.Strategy = dnsStrategy
			}
		}
		res, err := c.SetDNS(cfg)
		if err != nil {
			return err
		}
		return out(res, func() { fmt.Println("dns updated") })
	},
}

// joinAny renders a decoded JSON array of strings.
func joinAny(vals []any, sep string) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, str(v))
	}
	return strings.Join(parts, sep)
}

// ---- TUN / groups / endpoints -------------------------------------------

var tunCmd = &cobra.Command{
	Use:   "tun",
	Short: "TUN inbound options (only in effect in tun mode)",
}

var tunGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show TUN options",
	RunE: func(cmd *cobra.Command, args []string) error {
		t, err := sdk().TUN()
		if err != nil {
			return err
		}
		return out(t, func() {
			fmt.Printf("stack: %s   mtu: %d   strict_route: %v   auto_redirect: %v\n",
				dash(t.Stack), t.MTU, t.StrictRoute, t.AutoRedirect)
			if len(t.Address) > 0 {
				fmt.Printf("address: %v\n", t.Address)
			} else {
				fmt.Printf("address: %v (default)\n", apitypes.DefaultTUNAddresses)
			}
			if len(t.ExcludeProcess) > 0 {
				fmt.Printf("exclude_process: %v\n", t.ExcludeProcess)
			}
		})
	},
}

var (
	tunFile         string
	tunStack        string
	tunMTU          int
	tunStrict       bool
	tunAutoRedirect bool
	tunAddress      []string
)

var tunSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Update TUN options (-f for the whole doc, or patch single knobs)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := sdk()
		var cfg apitypes.TUNConfig
		if tunFile != "" {
			if err := readJSONArg(tunFile, &cfg); err != nil {
				return err
			}
		} else {
			cur, err := c.TUN()
			if err != nil {
				return err
			}
			cfg = cur
			if cmd.Flags().Changed("stack") {
				cfg.Stack = tunStack
			}
			if cmd.Flags().Changed("mtu") {
				cfg.MTU = tunMTU
			}
			if cmd.Flags().Changed("strict-route") {
				cfg.StrictRoute = tunStrict
			}
			if cmd.Flags().Changed("auto-redirect") {
				cfg.AutoRedirect = tunAutoRedirect
			}
			if cmd.Flags().Changed("address") {
				cfg.Address = append([]string(nil), tunAddress...)
			}
		}
		res, err := c.SetTUN(cfg)
		if err != nil {
			return err
		}
		return out(res, func() { fmt.Println("tun options updated") })
	},
}

var groupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "Proxy-group topology (Auto / Overseas / per-country / user groups)",
}

var groupsGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the group config",
	RunE: func(cmd *cobra.Command, args []string) error {
		g, err := sdk().ProxyGroups()
		if err != nil {
			return err
		}
		return emit(g) // nested config; JSON is the honest rendering
	},
}

var groupsFile string

var groupsSetCmd = &cobra.Command{
	Use:   "set -f <file|->",
	Short: "Replace the group config from a JSON document",
	RunE: func(cmd *cobra.Command, args []string) error {
		if groupsFile == "" {
			return fmt.Errorf("-f <file|-> is required (see `trust-proxy groups get`)")
		}
		var cfg any
		if err := readJSONArg(groupsFile, &cfg); err != nil {
			return err
		}
		res, err := sdk().SetProxyGroups(cfg)
		if err != nil {
			return err
		}
		return out(res, func() { fmt.Println("proxy groups updated") })
	},
}

var (
	foInterval  int
	foTolerance int
	foIdle      int
	foInterrupt bool
)

var groupsFailoverCmd = &cobra.Command{
	Use:   "failover",
	Short: "Show or tune how urltest groups switch node (affects Auto/Overseas/country/user groups)",
	Long: `Show or tune group failover.

An urltest group re-ranks its members on a timer and elects the fastest. The
knobs decide how twitchy that is:

  --probe-interval   how often members are re-probed (seconds)
  --tolerance        how much faster a challenger must be to win (ms). Bigger =
                     fewer switches. Cross-border latency jitters by tens of ms,
                     so a small value makes the group flap between equal nodes.
  --idle-timeout     stop probing after this long with no traffic (seconds)
  --interrupt        kill ALREADY-ESTABLISHED connections when the elected node
                     changes. Off by default: it is what makes a login or an
                     upload die halfway through. Real node failures do not need
                     it — a dead dial fails over immediately regardless.

With no flags this prints the current values.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c := sdk()
		cfg, err := c.ProxyGroupsConfig()
		if err != nil {
			return err
		}
		touched := false
		for _, f := range []string{"probe-interval", "tolerance", "idle-timeout", "interrupt"} {
			if cmd.Flags().Changed(f) {
				touched = true
			}
		}
		if !touched {
			return out(cfg.Failover, func() {
				fmt.Printf("probe interval : %ds\n", orDefault(cfg.Failover.ProbeIntervalSeconds, proxygroups.DefaultProbeInterval))
				fmt.Printf("tolerance      : %dms\n", orDefault(cfg.Failover.ToleranceMS, proxygroups.DefaultProbeTolerance))
				fmt.Printf("idle timeout   : %ds\n", orDefault(cfg.Failover.IdleTimeoutSeconds, proxygroups.DefaultIdleTimeout))
				fmt.Printf("interrupt live : %v\n", cfg.Failover.InterruptExistingConnections)
			})
		}
		if cmd.Flags().Changed("probe-interval") {
			cfg.Failover.ProbeIntervalSeconds = foInterval
		}
		if cmd.Flags().Changed("tolerance") {
			cfg.Failover.ToleranceMS = foTolerance
		}
		if cmd.Flags().Changed("idle-timeout") {
			cfg.Failover.IdleTimeoutSeconds = foIdle
		}
		if cmd.Flags().Changed("interrupt") {
			cfg.Failover.InterruptExistingConnections = foInterrupt
		}
		res, err := c.SetProxyGroupsConfig(cfg)
		if err != nil {
			return err
		}
		return out(res.Failover, func() { fmt.Println("failover updated") })
	},
}

// orDefault renders "unset" as the value the gateway will actually use, so the
// printed numbers match the running config instead of showing a bare 0.
func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

var endpointsCmd = &cobra.Command{
	Use:   "endpoints",
	Short: "WireGuard / Tailscale exit endpoints",
}

var endpointsLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List exit endpoints",
	RunE: func(cmd *cobra.Command, args []string) error {
		eps, err := sdk().Endpoints()
		if err != nil {
			return err
		}
		return out(eps, func() {
			if len(eps) == 0 {
				fmt.Println("(no endpoints)")
				return
			}
			fmt.Printf("%-18s %-12s %-6s %s\n", "TAG", "TYPE", "ON", "PEER/HOST")
			for _, e := range eps {
				target := e.PeerEndpoint
				if target == "" {
					target = e.Hostname
				}
				fmt.Printf("%-18s %-12s %-6s %s\n", e.Tag, e.Type, yesNo(e.Enabled), dash(target))
			}
		})
	},
}

var endpointsFile string

var endpointsAddCmd = &cobra.Command{
	Use:   "add -f <file|->",
	Short: "Register an exit endpoint from a JSON document",
	RunE: func(cmd *cobra.Command, args []string) error {
		if endpointsFile == "" {
			return fmt.Errorf("-f <file|-> is required (an endpoint doc: tag/type/private_key/peer_*)")
		}
		var e apitypes.Endpoint
		if err := readJSONArg(endpointsFile, &e); err != nil {
			return err
		}
		eps, err := sdk().AddEndpoint(e)
		if err != nil {
			return err
		}
		return out(eps, func() { fmt.Printf("added endpoint %s\n", e.Tag) })
	},
}

var endpointsToggleCmd = &cobra.Command{
	Use:   "toggle <tag>",
	Short: "Enable/disable an endpoint",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		eps, err := sdk().PatchEndpoint(args[0], customEnable)
		if err != nil {
			return err
		}
		return out(eps, func() { fmt.Printf("%s enabled=%v\n", args[0], customEnable) })
	},
}

var endpointsRmCmd = &cobra.Command{
	Use:   "rm <tag>",
	Short: "Remove an endpoint",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().DeleteEndpoint(args[0]); err != nil {
			return err
		}
		fmt.Println("removed", args[0])
		return nil
	},
}

// ---- proxies -------------------------------------------------------------

var proxiesCmd = &cobra.Command{
	Use:   "proxies",
	Short: "Proxy groups/members: list, select, measure delay",
}

var proxiesLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List proxies and groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := sdk().Proxies()
		if err != nil {
			return err
		}
		if jsonOut {
			return emit(p)
		}
		proxies, _ := p["proxies"].(map[string]any)
		fmt.Printf("%-28s %-12s %-20s %s\n", "NAME", "TYPE", "NOW", "MEMBERS")
		for _, name := range sortedKeys(proxies) {
			e, _ := proxies[name].(map[string]any)
			typ, _ := e["type"].(string)
			now, _ := e["now"].(string)
			all, _ := e["all"].([]any)
			members := ""
			if len(all) > 0 {
				members = fmt.Sprintf("%d", len(all))
			}
			fmt.Printf("%-28s %-12s %-20s %s\n", truncate(name, 28), typ, dash(now), members)
		}
		return nil
	},
}

var proxiesSelectCmd = &cobra.Command{
	Use:   "select <group> <member>",
	Short: "Point a selector group at one member",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().SelectProxy(args[0], args[1]); err != nil {
			return err
		}
		fmt.Printf("%s -> %s\n", args[0], args[1])
		return nil
	},
}

var proxiesDelayCmd = &cobra.Command{
	Use:   "delay <name>",
	Short: "Measure one proxy's latency",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		d, err := sdk().ProxyDelay(args[0])
		if err != nil {
			return err
		}
		return out(d, func() { fmt.Printf("%s: %v ms\n", args[0], d["delay"]) })
	},
}

// ---- proxy scores --------------------------------------------------------

var proxiesScoresCmd = &cobra.Command{
	Use:   "scores",
	Short: "Show how each node is scoring on real traffic (not just probe latency)",
	Long: `Show the live scoring table.

Groups rank their members by observed real traffic, not only by the
generate_204 probe. Each node's score combines three terms:

  reliability  dial successes/failures, with consecutive results amplified —
               the 3rd failure in a row costs 3x the first
  latency      real dial latency (median of the recent window)
  throughput   bytes/second on connections that moved enough data to judge

A node stays at a neutral 100 until it has accumulated MIN samples (shown as
"warming N/MIN"): a cold start must not demote a node the gateway may be about
to depend on. Equal scores are broken by latency.

The breaker column is separate from the score and works from the first sample.
An open breaker DEMOTES a node to last choice — it never removes it, because a
group whose every member was excluded at once would leave the machine with no
egress at all.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := sdk().ProxyScores()
		if err != nil {
			return err
		}
		if jsonOut {
			return emit(res)
		}
		if !res.Enabled {
			fmt.Println("scoring is disabled; groups rank on probe latency alone")
			fmt.Println()
		}
		fmt.Println(res.Formula)
		fmt.Printf("weights: reliability=%d latency=%d throughput=%d | min samples=%d | tie margin=%d pts\n\n",
			res.Config.WeightReliability, res.Config.WeightLatency, res.Config.WeightThroughput,
			res.Config.MinSamples, res.Config.TieMarginPoints)
		if len(res.Scores) == 0 {
			fmt.Println("no group members yet (add nodes with `trust-proxy sub apply`)")
			return nil
		}
		fmt.Printf("%-26s %-18s %-6s %-6s %-6s %-8s %-9s %s\n",
			"TAG", "SCORE", "REL", "LAT", "TP", "LATENCY", "STREAK", "STATE")
		for _, s := range res.Scores {
			lat := "-"
			if s.LatencyMS > 0 {
				lat = fmt.Sprintf("%dms", s.LatencyMS)
			}
			fmt.Printf("%-26s %-18s %-6.0f %-6.0f %-6.0f %-8s %-9s %s\n",
				truncate(s.Tag, 26), scoreText(s), s.Reliability, s.Latency, s.Throughput,
				lat, streakText(s), scoreState(s))
		}
		return nil
	},
}

// scoreColWidth is the SCORE column; the widest cell is the warming form.
const scoreColWidth = 18

// scoreText renders the score. A warming node prints its sample progress
// beside the 100: a bare 100 reads as "measured and excellent", which is the
// opposite of what it means.
func scoreText(s apitypes.ProxyScore) string {
	if s.Warming {
		return fmt.Sprintf("%.0f (warming %d/%d)", s.Score, s.Samples, s.MinSamples)
	}
	return fmt.Sprintf("%.0f", s.Score)
}

// streakText shows the consecutive-result counter that drives the amplified
// reward/penalty, so a big score move has a visible cause.
func streakText(s apitypes.ProxyScore) string {
	switch {
	case s.FailStreak > 0:
		return fmt.Sprintf("%d fail", s.FailStreak)
	case s.OKStreak > 0:
		return fmt.Sprintf("%d ok", s.OKStreak)
	}
	return "-"
}

func scoreState(s apitypes.ProxyScore) string {
	if !s.Preferred {
		st := "demoted (breaker " + dashDefault(s.Breaker, "open") + ")"
		if s.BreakerRemaining > 0 {
			st += fmt.Sprintf(", %ds left", s.BreakerRemaining)
		}
		return st
	}
	if s.Warming {
		return "warming"
	}
	if s.LastErr != "" {
		return "ok, last error: " + truncate(s.LastErr, 40)
	}
	return "ok"
}

var proxiesScoresResetCmd = &cobra.Command{
	Use:   "scores-reset",
	Short: "Discard every observation and put all nodes back into warm-up",
	Long: `Throw away the measured scores.

For when the numbers describe a path that no longer exists — a new
subscription, a different network. Observations also expire on their own after
the configured stale window.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().ResetProxyScores(); err != nil {
			return err
		}
		fmt.Println("proxy scores reset; every node is back at 100 (warming)")
		return nil
	},
}

// ---- groups scoring ------------------------------------------------------

var (
	scMinSamples int
	scWRel       int
	scWLat       int
	scWTp        int
	scReward     int
	scPenalty    int
	scMaxStreak  int
	scLatGood    int
	scLatBad     int
	scTpGood     int
	scTieMargin  int
	scBreakFails int
	scBreakDelay int
	scBreakOKs   int
	scStale      int
	scDisabled   bool
)

var scoringFlags = []string{
	"min-samples", "weight-reliability", "weight-latency", "weight-throughput",
	"reward", "penalty", "max-streak", "latency-good", "latency-bad",
	"throughput-good", "tie-margin", "breaker-failures", "breaker-delay",
	"breaker-successes", "stale-hours", "disabled",
}

func weightTouched(cmd *cobra.Command) bool {
	return cmd.Flags().Changed("weight-reliability") ||
		cmd.Flags().Changed("weight-latency") ||
		cmd.Flags().Changed("weight-throughput")
}

func zeroWeights(c apitypes.ProxyScoring) bool {
	return c.WeightReliability <= 0 && c.WeightLatency <= 0 && c.WeightThroughput <= 0
}

var groupsScoringCmd = &cobra.Command{
	Use:   "scoring",
	Short: "Show or tune how nodes are scored on real traffic",
	Long: `Show or tune the scoring policy (see ` + "`trust-proxy proxies scores`" + ` for the result).

  --min-samples         real outcomes before a node's score leaves the neutral
                        100. Lower = reacts sooner but judges on less evidence.
  --weight-*            relative weights of the three terms. They are ratios,
                        not percentages: 50/30/20 and 5/3/2 behave identically.
                        A weight of 0 turns that term off.
  --reward/--penalty    points per success/failure, multiplied by the current
                        consecutive streak (capped by --max-streak).
  --latency-good/-bad   ms that score 100 and 0; linear between.
  --throughput-good     KB/s that scores 100.
  --tie-margin          score differences below this count as equal, and the
                        tie is broken by latency.
  --breaker-*           the circuit breaker, which is orthogonal to the score
                        and works from the first sample. An open breaker only
                        demotes a node to last choice, never removes it.
  --stale-hours         discard observations older than this on restart.
  --disabled            turn scoring off entirely; groups then rank on probe
                        latency alone, exactly as before this feature existed.

With no flags this prints the values in force.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c := sdk()
		cfg, err := c.ProxyGroupsConfig()
		if err != nil {
			return err
		}
		touched := false
		for _, f := range scoringFlags {
			if cmd.Flags().Changed(f) {
				touched = true
			}
		}
		if !touched {
			// Read the resolved values back from the gateway rather than
			// re-deriving defaults here: a second copy of the defaults would
			// drift, and the point of this view is what is actually in force.
			live, err := c.ProxyScores()
			if err != nil {
				return err
			}
			return out(live.Config, func() {
				k := live.Config
				fmt.Println(live.Formula)
				fmt.Println()
				fmt.Printf("enabled            : %v\n", live.Enabled)
				fmt.Printf("min samples        : %d\n", k.MinSamples)
				fmt.Printf("weights            : reliability=%d latency=%d throughput=%d\n",
					k.WeightReliability, k.WeightLatency, k.WeightThroughput)
				fmt.Printf("reward / penalty   : +%d / -%d per result, streak x up to %d\n",
					k.RewardPerSuccess, k.PenaltyPerFailure, k.MaxStreak)
				fmt.Printf("latency 100 / 0    : %dms / %dms\n", k.LatencyGoodMS, k.LatencyBadMS)
				fmt.Printf("throughput 100     : %d KB/s\n", k.ThroughputGoodKBps)
				fmt.Printf("tie margin         : %d points (then lowest latency wins)\n", k.TieMarginPoints)
				fmt.Printf("breaker            : opens after %d failures, %ds, closes after %d successes\n",
					k.BreakerFailures, k.BreakerDelaySeconds, k.BreakerSuccesses)
				fmt.Printf("stale after        : %dh\n", k.StaleHours)
			})
		}
		patch := map[string]*int{
			"min-samples":        &cfg.Scoring.MinSamples,
			"weight-reliability": &cfg.Scoring.WeightReliability,
			"weight-latency":     &cfg.Scoring.WeightLatency,
			"weight-throughput":  &cfg.Scoring.WeightThroughput,
			"reward":             &cfg.Scoring.RewardPerSuccess,
			"penalty":            &cfg.Scoring.PenaltyPerFailure,
			"max-streak":         &cfg.Scoring.MaxStreak,
			"latency-good":       &cfg.Scoring.LatencyGoodMS,
			"latency-bad":        &cfg.Scoring.LatencyBadMS,
			"throughput-good":    &cfg.Scoring.ThroughputGoodKBps,
			"tie-margin":         &cfg.Scoring.TieMarginPoints,
			"breaker-failures":   &cfg.Scoring.BreakerFailures,
			"breaker-delay":      &cfg.Scoring.BreakerDelaySeconds,
			"breaker-successes":  &cfg.Scoring.BreakerSuccesses,
			"stale-hours":        &cfg.Scoring.StaleHours,
		}
		values := map[string]int{
			"min-samples": scMinSamples, "weight-reliability": scWRel,
			"weight-latency": scWLat, "weight-throughput": scWTp,
			"reward": scReward, "penalty": scPenalty, "max-streak": scMaxStreak,
			"latency-good": scLatGood, "latency-bad": scLatBad,
			"throughput-good": scTpGood, "tie-margin": scTieMargin,
			"breaker-failures": scBreakFails, "breaker-delay": scBreakDelay,
			"breaker-successes": scBreakOKs, "stale-hours": scStale,
		}
		for name, dst := range patch {
			if cmd.Flags().Changed(name) {
				*dst = values[name]
			}
		}
		if cmd.Flags().Changed("disabled") {
			cfg.Scoring.Disabled = scDisabled
		}
		// The three weights are one value, not three. Each is omitempty, and
		// all-three-zero means "unset" to the store — so setting exactly one of
		// them to 0 ("stop counting throughput") would leave a document the
		// gateway reads back as defaults, silently turning the term on again.
		// Materialise the other two from what is actually in force.
		if weightTouched(cmd) && zeroWeights(cfg.Scoring) {
			live, err := c.ProxyScores()
			if err != nil {
				return err
			}
			for _, w := range []struct {
				name string
				dst  *int
				from int
			}{
				{"weight-reliability", &cfg.Scoring.WeightReliability, live.Config.WeightReliability},
				{"weight-latency", &cfg.Scoring.WeightLatency, live.Config.WeightLatency},
				{"weight-throughput", &cfg.Scoring.WeightThroughput, live.Config.WeightThroughput},
			} {
				if !cmd.Flags().Changed(w.name) {
					*w.dst = w.from
				}
			}
			if zeroWeights(cfg.Scoring) {
				return fmt.Errorf("all three weights are 0; scoring needs at least one term (see `trust-proxy groups scoring --disabled` to turn it off instead)")
			}
		}
		res, err := c.SetProxyGroupsConfig(cfg)
		if err != nil {
			return err
		}
		return out(res.Scoring, func() { fmt.Println("scoring updated") })
	},
}

// ---- auto-block ----------------------------------------------------------

var autoBlockCmd = &cobra.Command{
	Use:       "autoblock <on|off>",
	Short:     "Auto-drop connections that hit a threat-intel indicator",
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"on", "off"},
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := sdk().AutoBlock(args[0] == "on")
		if err != nil {
			return err
		}
		return out(res, func() { fmt.Printf("auto-block: %s\n", args[0]) })
	},
}

func init() {
	modeSetCmd.Flags().IntVar(&modeGuard, "guard", 60, "auto-revert after N seconds unless confirmed (0 = no guard)")
	for _, c := range []*cobra.Command{modeSetCmd, postureSetCmd, routingSetCmd} {
		c.Flags().BoolVarP(&yesToAll, "yes", "y", false, "skip the confirmation prompt")
	}
	dnsSetCmd.Flags().StringVarP(&dnsFile, "file", "f", "", "read the whole DNS policy from this JSON file (- for stdin)")
	dnsSetCmd.Flags().StringVar(&dnsDirectServer, "direct-server", "", "resolver for direct-routed domains (ip, ip:port or hostname)")
	dnsSetCmd.Flags().BoolVar(&dnsDisplitSet, "disable-direct-split", false, "resolve everything through the servers above (not recommended)")
	dnsSetCmd.Flags().StringVar(&dnsFinal, "final", "", "fallback server tag")
	dnsSetCmd.Flags().StringVar(&dnsStrategy, "strategy", "", "prefer_ipv4|prefer_ipv6|ipv4_only|ipv6_only")
	tunSetCmd.Flags().StringVarP(&tunFile, "file", "f", "", "read the whole TUN config from this JSON file (- for stdin)")
	tunSetCmd.Flags().StringVar(&tunStack, "stack", "", "system|gvisor|mixed")
	tunSetCmd.Flags().IntVar(&tunMTU, "mtu", 0, "MTU (0 = auto)")
	tunSetCmd.Flags().BoolVar(&tunStrict, "strict-route", true, "strict route")
	tunSetCmd.Flags().BoolVar(&tunAutoRedirect, "auto-redirect", true, "Linux: nftables redirect so Docker/containerd bridge egress hits the same Permit/detect path (no-op on macOS/Windows)")
	tunSetCmd.Flags().StringSliceVar(&tunAddress, "address", nil, "TUN interface CIDRs (empty = default 198.18.0.1/30 + ULA; avoids Docker 172.16/12)")
	groupsSetCmd.Flags().StringVarP(&groupsFile, "file", "f", "", "JSON document (- for stdin)")
	groupsFailoverCmd.Flags().IntVar(&foInterval, "probe-interval", proxygroups.DefaultProbeInterval, "seconds between urltest probes (min 10)")
	groupsFailoverCmd.Flags().IntVar(&foTolerance, "tolerance", proxygroups.DefaultProbeTolerance, "ms a challenger must beat the current node by; bigger = fewer switches")
	groupsFailoverCmd.Flags().IntVar(&foIdle, "idle-timeout", proxygroups.DefaultIdleTimeout, "seconds without traffic before probing stops")
	groupsFailoverCmd.Flags().BoolVar(&foInterrupt, "interrupt", false, "kill live connections when the elected node changes (breaks logins/uploads mid-flight)")
	// Scoring knobs. Flag defaults are 0 = "unset"; only flags the user actually
	// changed are patched, so the gateway keeps resolving the rest. Printing the
	// real defaults here would mean a second copy of them that could drift —
	// `groups scoring` with no flags reads them back from the gateway instead.
	groupsScoringCmd.Flags().IntVar(&scMinSamples, "min-samples", 0, "real outcomes before a node's score leaves the neutral 100")
	groupsScoringCmd.Flags().IntVar(&scWRel, "weight-reliability", 0, "relative weight of the reliability term (0 = ignore it)")
	groupsScoringCmd.Flags().IntVar(&scWLat, "weight-latency", 0, "relative weight of the latency term (0 = ignore it)")
	groupsScoringCmd.Flags().IntVar(&scWTp, "weight-throughput", 0, "relative weight of the throughput term (0 = ignore it)")
	groupsScoringCmd.Flags().IntVar(&scReward, "reward", 0, "points per success, multiplied by the consecutive-success streak")
	groupsScoringCmd.Flags().IntVar(&scPenalty, "penalty", 0, "points per failure, multiplied by the consecutive-failure streak")
	groupsScoringCmd.Flags().IntVar(&scMaxStreak, "max-streak", 0, "cap on the streak multiplier")
	groupsScoringCmd.Flags().IntVar(&scLatGood, "latency-good", 0, "ms that scores 100 on the latency term")
	groupsScoringCmd.Flags().IntVar(&scLatBad, "latency-bad", 0, "ms that scores 0 on the latency term")
	groupsScoringCmd.Flags().IntVar(&scTpGood, "throughput-good", 0, "KB/s that scores 100 on the throughput term")
	groupsScoringCmd.Flags().IntVar(&scTieMargin, "tie-margin", 0, "score gap below which the lowest latency wins instead")
	groupsScoringCmd.Flags().IntVar(&scBreakFails, "breaker-failures", 0, "consecutive failures that open a node's breaker")
	groupsScoringCmd.Flags().IntVar(&scBreakDelay, "breaker-delay", 0, "seconds an open breaker stays open before a trial dial")
	groupsScoringCmd.Flags().IntVar(&scBreakOKs, "breaker-successes", 0, "trial successes needed to close the breaker again")
	groupsScoringCmd.Flags().IntVar(&scStale, "stale-hours", 0, "discard observations older than this on restart")
	groupsScoringCmd.Flags().BoolVar(&scDisabled, "disabled", false, "turn scoring off; groups rank on probe latency alone")
	endpointsAddCmd.Flags().StringVarP(&endpointsFile, "file", "f", "", "JSON endpoint document (- for stdin)")
	endpointsToggleCmd.Flags().BoolVar(&customEnable, "enabled", true, "target state")

	modeCmd.AddCommand(modeGetCmd, modeSetCmd, modeConfirmCmd)
	routingCmd.AddCommand(routingGetCmd, routingSetCmd)
	postureCmd.AddCommand(postureGetCmd, postureSetCmd)
	finalCmd.AddCommand(finalGetCmd, finalSetCmd)
	dnsQueriesCmd.Flags().IntVar(&dnsQueriesTop, "top", 10, "how many parent domains to show")
	dnsCmd.AddCommand(dnsGetCmd, dnsSetCmd, dnsQueriesCmd)
	tunCmd.AddCommand(tunGetCmd, tunSetCmd)
	groupsCmd.AddCommand(groupsGetCmd, groupsSetCmd, groupsFailoverCmd, groupsScoringCmd)
	endpointsCmd.AddCommand(endpointsLsCmd, endpointsAddCmd, endpointsToggleCmd, endpointsRmCmd)
	proxiesCmd.AddCommand(proxiesLsCmd, proxiesSelectCmd, proxiesDelayCmd, proxiesScoresCmd, proxiesScoresResetCmd)
}
