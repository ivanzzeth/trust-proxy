package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// ---- proxy inbound listen point -----------------------------------------

var inboundCmd = &cobra.Command{
	Use:   "inbound",
	Short: "Where the mixed (socks/http) proxy inbound listens",
	Long: "The listen point used to be reachable only by hand-editing <data>/config.json,\n" +
		"which the docs say not to hand-edit. Credentials are not here: they come from\n" +
		"the account list (`trust-proxy user set <name> --proxy-password`).",
}

var inboundGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the listen address and port (and any pending guarded revert)",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := sdk().InboundListen()
		if err != nil {
			return err
		}
		return out(st, func() {
			fmt.Printf("listen: %s:%d\n", st.Resolved.Listen, st.Resolved.Port)
			// Saying which halves are chosen and which are inherited matters here:
			// somebody who reads "127.0.0.1" as a decision will keep re-sending it
			// and freeze today's default into the store forever.
			if st.Listen.Listen == "" && st.Listen.Port == 0 {
				fmt.Println("source: defaults (nothing configured)")
			} else {
				fmt.Printf("configured: address=%s port=%s\n",
					dash(st.Listen.Listen), dashInt(st.Listen.Port))
			}
			if st.Revert != nil {
				fmt.Printf("PENDING REVERT: back to %s:%d in %ds unless you run `trust-proxy inbound confirm`\n",
					st.Revert.To.Resolved().Listen, st.Revert.To.Resolved().Port, st.Revert.InSeconds)
			}
		})
	},
}

var (
	inboundListen string
	inboundPort   int
	inboundGuard  int
)

var inboundSetCmd = &cobra.Command{
	Use:   "set [--listen ADDR] [--port N]",
	Short: "Move the proxy inbound (guarded by default: auto-reverts unless confirmed)",
	Long: "The guard is a dead-man's switch, and it matters more here than for `mode set`:\n" +
		"a wrong address does not fail. The rebuild succeeds and the gateway serves a\n" +
		"port nothing is pointed at, so nothing looks broken from the gateway's side.\n\n" +
		"Listening off loopback is refused unless some account has a proxy password —\n" +
		"otherwise the machine becomes an open proxy for anyone who can route to it.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !cmd.Flags().Changed("listen") && !cmd.Flags().Changed("port") {
			return fmt.Errorf("nothing to change: give --listen and/or --port (see `trust-proxy inbound get`)")
		}
		c := sdk()
		st, err := c.InboundListen()
		if err != nil {
			return err
		}
		want := st.Listen // patch the stored value, keeping blanks blank
		if cmd.Flags().Changed("listen") {
			want.Listen = inboundListen
		}
		if cmd.Flags().Changed("port") {
			want.Port = inboundPort
		}
		if cmd.Flags().Changed("listen") && !isLoopbackAddr(inboundListen) {
			if err := confirm("listening off loopback exposes this proxy to everything that can reach this machine. Continue?"); err != nil {
				return err
			}
		}
		res, err := c.SetInboundListen(want, inboundGuard)
		if err != nil {
			return err
		}
		return out(res, func() {
			fmt.Printf("inbound -> %s:%d\n", res.Resolved.Listen, res.Resolved.Port)
			if inboundGuard > 0 {
				fmt.Printf("guard armed: reverts in %ds unless you run `trust-proxy inbound confirm`\n", inboundGuard)
				fmt.Printf("verify first: curl -x socks5h://%s:%d https://api.ipify.org\n",
					res.Resolved.Listen, res.Resolved.Port)
			}
		})
	},
}

var inboundConfirmCmd = &cobra.Command{
	Use:   "confirm",
	Short: "Confirm the last guarded listen change (cancels the pending revert)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().ConfirmInboundListen(); err != nil {
			return err
		}
		fmt.Println("confirmed; no revert pending")
		return nil
	},
}

// isLoopbackAddr is only for the confirmation prompt; the gateway does the
// authoritative check (it is the side that knows whether any account has a
// proxy password).
func isLoopbackAddr(s string) bool {
	return s == "" || s == "127.0.0.1" || s == "::1" || s == "localhost"
}

// ---- log + history retention --------------------------------------------

var retentionCmd = &cobra.Command{
	Use:   "retention",
	Short: "How much of the daemon log and connection history stays on disk",
	Long: "These were eight `serve` flags, which made them unsettable in practice: the\n" +
		"gateway runs as a system service, so the flags live in the launchd plist /\n" +
		"systemd unit, and a bare `trust-proxy install` — the documented upgrade path —\n" +
		"rewrites that definition without them.",
}

var retentionGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the retention policy (unset knobs show the default in force)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := sdk()
		r, err := c.Retention()
		if err != nil {
			return err
		}
		if jsonOut {
			return emit(r)
		}
		// Printing a blank where a default is in force would read as "off". Ask the
		// gateway what its defaults are rather than restating them here — a second
		// copy of the numbers does not fail loudly when they change.
		def, err := c.Defaults()
		if err != nil {
			return err
		}
		printRetentionRule("log", r.Log, def.Retention.Log)
		printRetentionRule("history", r.History, def.Retention.History)
		return nil
	},
}

func printRetentionRule(name string, got, def apitypes.RetentionRule) {
	fmt.Printf("%s:\n", name)
	fmt.Printf("  max size    %s\n", sizeOrDefault(got.MaxSizeMB, def.MaxSizeMB))
	fmt.Printf("  keep        %s\n", intOrDefault(got.MaxBackups, def.MaxBackups, "generations"))
	fmt.Printf("  max age     %s\n", ageOrDefault(got.MaxAgeDays, def.MaxAgeDays))
	fmt.Printf("  compress    %v%s\n", got.CompressOr(def.CompressOr(true)), defaultNote(got.Compress == nil))
}

func sizeOrDefault(got, def int) string {
	if got < 0 {
		return "unlimited (rotation off)"
	}
	if got == 0 {
		return fmt.Sprintf("%d MB (default)", def)
	}
	return fmt.Sprintf("%d MB", got)
}

func intOrDefault(got, def int, unit string) string {
	if got == 0 {
		return fmt.Sprintf("%d %s (default)", def, unit)
	}
	return fmt.Sprintf("%d %s", got, unit)
}

func ageOrDefault(got, def int) string {
	if got == 0 && def == 0 {
		return "by count only (default)"
	}
	if got == 0 {
		return fmt.Sprintf("%d days (default)", def)
	}
	return fmt.Sprintf("%d days", got)
}

func defaultNote(isDefault bool) string {
	if isDefault {
		return " (default)"
	}
	return ""
}

func dashInt(n int) string {
	if n == 0 {
		return tableSkip
	}
	return fmt.Sprint(n)
}

var (
	retLogMaxSize  int
	retLogKeep     int
	retLogMaxAge   int
	retLogCompress bool
	retHistMaxSize int
	retHistKeep    int
	retHistMaxAge  int
	retHistComp    bool
)

var retentionSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Patch retention knobs (only the flags you give are changed)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := sdk()
		cur, err := c.Retention()
		if err != nil {
			return err
		}
		changed := false
		patch := func(name string, apply func()) {
			if cmd.Flags().Changed(name) {
				apply()
				changed = true
			}
		}
		patch("log-max-size", func() { cur.Log.MaxSizeMB = retLogMaxSize })
		patch("log-keep", func() { cur.Log.MaxBackups = retLogKeep })
		patch("log-max-age", func() { cur.Log.MaxAgeDays = retLogMaxAge })
		patch("log-compress", func() { cur.Log.Compress = &retLogCompress })
		patch("history-max-size", func() { cur.History.MaxSizeMB = retHistMaxSize })
		patch("history-keep", func() { cur.History.MaxBackups = retHistKeep })
		patch("history-max-age", func() { cur.History.MaxAgeDays = retHistMaxAge })
		patch("history-compress", func() { cur.History.Compress = &retHistComp })
		if !changed {
			return fmt.Errorf("nothing to change (see `trust-proxy retention get`)")
		}
		res, err := c.SetRetention(cur)
		if err != nil {
			return err
		}
		return out(res, func() { fmt.Println("retention updated (in force now; no restart needed)") })
	},
}

// ---- defaults ------------------------------------------------------------

var defaultsCmd = &cobra.Command{
	Use:   "defaults",
	Short: "Every domain's built-in configuration, as the gateway itself computes it",
	Long: "The gateway is the only source of these numbers. Anything rendering\n" +
		"\"(default 32 MB)\" reads them from here rather than carrying its own copy,\n" +
		"which would not fail loudly when the gateway changes — it would just start\n" +
		"describing a gateway that no longer exists.",
	RunE: func(cmd *cobra.Command, args []string) error {
		d, err := sdk().Defaults()
		if err != nil {
			return err
		}
		return out(d, func() {
			fmt.Printf("inbound     %s:%d\n", d.Inbound.Listen, d.Inbound.Port)
			fmt.Printf("log         %d MB, keep %d, compress %v\n",
				d.Retention.Log.MaxSizeMB, d.Retention.Log.MaxBackups, d.Retention.Log.CompressOr(true))
			fmt.Printf("history     %d MB, keep %d, compress %v\n",
				d.Retention.History.MaxSizeMB, d.Retention.History.MaxBackups, d.Retention.History.CompressOr(true))
			fmt.Printf("tun         stack=%s address=%v auto_redirect=%v\n",
				d.TUN.Stack, d.TUN.Address, d.TUN.AutoRedirect)
			fmt.Printf("failover    probe %ds, tolerance %dms, interrupt %v\n",
				d.Failover.ProbeIntervalSeconds, d.Failover.ToleranceMS, d.Failover.InterruptExistingConnections)
			fmt.Printf("scoring     min_samples %d, weights rel/lat/tp %d/%d/%d\n",
				d.Scoring.MinSamples, d.Scoring.WeightReliability, d.Scoring.WeightLatency, d.Scoring.WeightThroughput)
			fmt.Println("(the full document, including DNS and every detection threshold, is in --json)")
		})
	},
}

func init() {
	inboundSetCmd.Flags().StringVar(&inboundListen, "listen", "", "listen address (e.g. 127.0.0.1, 0.0.0.0)")
	inboundSetCmd.Flags().IntVar(&inboundPort, "port", 0, "listen port (0 = the built-in default)")
	inboundSetCmd.Flags().IntVar(&inboundGuard, "guard", 60, "auto-revert after N seconds unless confirmed (0 = no guard)")
	// This command prompts (off-loopback), so it needs the escape hatch every
	// other prompting command has. Without it the prompt is unanswerable from a
	// script and `-y` fails as an unknown flag — which reads as "this command
	// does not support that", not "the flag was never registered".
	inboundSetCmd.Flags().BoolVarP(&yesToAll, "yes", "y", false, "skip the confirmation prompt")
	inboundCmd.AddCommand(inboundGetCmd, inboundSetCmd, inboundConfirmCmd)

	retentionSetCmd.Flags().IntVar(&retLogMaxSize, "log-max-size", 0, "rotate the daemon log past N MB (-1 = never rotate)")
	retentionSetCmd.Flags().IntVar(&retLogKeep, "log-keep", 0, "rotated log generations to keep")
	retentionSetCmd.Flags().IntVar(&retLogMaxAge, "log-max-age", 0, "delete rotated logs older than N days (0 = by count only)")
	retentionSetCmd.Flags().BoolVar(&retLogCompress, "log-compress", true, "gzip rotated logs")
	retentionSetCmd.Flags().IntVar(&retHistMaxSize, "history-max-size", 0, "rotate the connection history past N MB")
	retentionSetCmd.Flags().IntVar(&retHistKeep, "history-keep", 0, "rotated history generations to keep")
	retentionSetCmd.Flags().IntVar(&retHistMaxAge, "history-max-age", 0, "delete rotated history older than N days")
	retentionSetCmd.Flags().BoolVar(&retHistComp, "history-compress", true, "gzip rotated history")
	retentionCmd.AddCommand(retentionGetCmd, retentionSetCmd)

	// Registered in root.go's client list, not here: these talk to a running
	// backend, so they need --api-addr/--api-token/--json like every other client
	// command. Adding them straight to rootCmd got them mounted without those
	// flags, and `inbound get --api-addr …` answered "unknown flag" — which reads
	// as "the command does not exist" rather than "it is wired to the wrong place".
	// backend, so they need --api-addr/--api-token/--json like every other
	// client command. Adding them straight to rootCmd got them mounted without
	// those flags, and `inbound get --api-addr …` answered "unknown flag" —
	// which reads as "the command does not exist" rather than "it is wired to
	// the wrong place".
}
