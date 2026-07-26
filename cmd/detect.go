package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// detectCmd exposes the detection engine's tunables and the gateway's own
// quarantine list. Both used to be unreachable: the thresholds were constants
// (a rebuild to change how noisy beaconing is) and self-inflicted blocks landed
// in the operator's deny list, where an unrelated posture switch wiped them.
var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "Detection thresholds (beacon / DGA / exfil) and disposal policy",
}

var detectGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show the effective detection settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := sdk().DetectionConfig()
		if err != nil {
			return err
		}
		return out(cfg, func() {
			fmt.Printf("beacon:   %s  min-sample=%d cv=%.2f window=%ds..%ds re-alert=%ds x%d\n",
				enabledWord(cfg.BeaconEnabled), cfg.BeaconMinSample, cfg.BeaconCV,
				cfg.BeaconMinInterval, cfg.BeaconMaxInterval, cfg.BeaconReAlert, cfg.BeaconReAlertFactor)
			fmt.Printf("dga:      %s  sld>=%d entropy>=%.1f | tunnel label>=%d entropy>=%.1f | subdomains>=%d\n",
				enabledWord(cfg.DGAEnabled), cfg.DGAMinLabelLen, cfg.DGAMinEntropy,
				cfg.TunnelMinLabelLen, cfg.TunnelMinEntropy, cfg.SubdomainAlertAt)
			fmt.Printf("exfil:    upload>=%s  ratio>=%.1f  new-dest-window=%dh\n",
				humanBytes(cfg.ExfilUploadBytes), cfg.ExfilMinRatio, cfg.ExfilNewDestHours)
			fmt.Printf("dns:      window=%ds  nxdomain-burst=%d  parent-rate=%d  odd-type=%d\n",
				cfg.QueryWindowSec, cfg.QueryNXBurst, cfg.QueryParentRate, cfg.QueryOddTypeAt)
			fmt.Printf("disposal: auto-block=%s  require-warm-permit=%s\n",
				yesNo(cfg.AutoBlock), yesNo(cfg.RequireWarmPermit))
		})
	},
}

var (
	detBeaconEnabled  bool
	detBeaconSample   int
	detBeaconCV       float64
	detBeaconMin      int
	detBeaconMax      int
	detBeaconReAlert  int
	detBeaconFactor   int
	detDGAEnabled     bool
	detDGALabel       int
	detDGAEntropy     float64
	detTunnelLabel    int
	detTunnelEntropy  float64
	detSubdomainAt    int
	detExfilBytes     int64
	detExfilRatio     float64
	detExfilNewHours  int
	detQueryWindow    int
	detQueryNX        int
	detQueryRate      int
	detQueryOddAt     int
	detAutoBlock      bool
	detRequireWarm    bool
	detectSettingsSet = map[string]func(*apitypes.DetectionConfig){}
)

var detectSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Change detection thresholds (only the flags you pass)",
	Long: "Every threshold is a knob rather than a constant. Notably:\n" +
		"  --beacon-realert-factor  a cadence is reported at most once per this many of\n" +
		"                           its own periods; a cooldown shorter than the cadence\n" +
		"                           re-reports every cycle and buries real findings.\n" +
		"  --exfil-min-ratio        upload/download ratio that counts as exfil-shaped (0 = ignore)\n" +
		"  --exfil-new-dest-hours   a destination unseen in this window counts as new (0 = ignore)\n" +
		"  --require-warm-permit    hold disposal until the Permit index is built, so a\n" +
		"                           large upload at startup can't ban an approved destination",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := sdk()
		cfg, err := c.DetectionConfig()
		if err != nil {
			return err
		}
		for flag, apply := range detectSettingsSet {
			if cmd.Flags().Changed(flag) {
				apply(&cfg)
			}
		}
		res, err := c.SetDetectionConfig(cfg)
		if err != nil {
			return err
		}
		return out(res, func() { fmt.Println("detection settings updated") })
	},
}

// ---- quarantine ----------------------------------------------------------

var quarantineCmd = &cobra.Command{
	Use:   "quarantine",
	Short: "Destinations the gateway blocked by itself (survives posture switches)",
}

var quarantineLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List quarantined destinations",
	RunE: func(cmd *cobra.Command, args []string) error {
		entries, err := sdk().Quarantine()
		if err != nil {
			return err
		}
		return out(entries, func() {
			if len(entries) == 0 {
				fmt.Println("(nothing quarantined)")
				return
			}
			fmt.Printf("%-40s %-5s %-22s %s\n", "VALUE", "KIND", "WHEN", "REASON")
			for _, e := range entries {
				kind := "host"
				if e.IsIP {
					kind = "ip"
				}
				fmt.Printf("%-40s %-5s %-22s %s\n", truncate(e.Value, 40), kind, truncate(e.Time, 22), e.Reason)
			}
		})
	},
}

var quarantineReleaseAll bool

var quarantineReleaseCmd = &cobra.Command{
	Use:   "release [value]",
	Short: "Release a quarantined destination (false positive)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := sdk()
		if quarantineReleaseAll {
			entries, err := c.ClearQuarantine()
			if err != nil {
				return err
			}
			return out(entries, func() { fmt.Println("quarantine cleared") })
		}
		if len(args) != 1 {
			return fmt.Errorf("give a value to release, or --all")
		}
		entries, err := c.ReleaseQuarantine(args[0])
		if err != nil {
			return err
		}
		return out(entries, func() { fmt.Printf("released %s (%d still quarantined)\n", args[0], len(entries)) })
	},
}

// humanBytes renders a byte count for the settings table.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.0f%ciB", float64(n)/float64(div), "KMGT"[exp])
}

func init() {
	f := detectSetCmd.Flags()
	f.BoolVar(&detBeaconEnabled, "beacon", true, "enable beaconing detection")
	f.IntVar(&detBeaconSample, "beacon-min-sample", 6, "connections observed before a cadence is judged")
	f.Float64Var(&detBeaconCV, "beacon-cv", 0.25, "max interval coefficient of variation")
	f.IntVar(&detBeaconMin, "beacon-min-interval", 5, "ignore cadences faster than this (seconds)")
	f.IntVar(&detBeaconMax, "beacon-max-interval", 7200, "ignore cadences slower than this (seconds)")
	f.IntVar(&detBeaconReAlert, "beacon-realert", 600, "floor for the re-alert cooldown (seconds)")
	f.IntVar(&detBeaconFactor, "beacon-realert-factor", 36, "cooldown = this many observed periods")
	f.BoolVar(&detDGAEnabled, "dga", true, "enable DGA / DNS-tunnel scoring")
	f.IntVar(&detDGALabel, "dga-min-label", 12, "minimum registrable label length to score")
	f.Float64Var(&detDGAEntropy, "dga-min-entropy", 3.8, "minimum Shannon entropy for a DGA-like label")
	f.IntVar(&detTunnelLabel, "tunnel-min-label", 25, "subdomain label length that suggests encoded data")
	f.Float64Var(&detTunnelEntropy, "tunnel-min-entropy", 4.0, "entropy for a tunnel-like subdomain label")
	f.IntVar(&detSubdomainAt, "subdomain-alert-at", 40, "distinct subdomains under one parent before alerting")
	f.Int64Var(&detExfilBytes, "exfil-upload-bytes", 10<<20, "upload size that makes a connection interesting")
	f.Float64Var(&detExfilRatio, "exfil-min-ratio", 4, "upload/download ratio counting as exfil-shaped (0 = ignore)")
	f.IntVar(&detExfilNewHours, "exfil-new-dest-hours", 24, "a destination unseen this long counts as new (0 = ignore)")
	f.IntVar(&detQueryWindow, "query-window", 300, "window for query-level counting (seconds)")
	f.IntVar(&detQueryNX, "query-nxdomain-burst", 30, "NXDOMAIN answers per client per window (0 = ignore)")
	f.IntVar(&detQueryRate, "query-parent-rate", 300, "queries under one parent per window (0 = ignore)")
	f.IntVar(&detQueryOddAt, "query-odd-type-at", 20, "TXT/NULL/ANY queries under one parent (0 = ignore)")
	f.BoolVar(&detAutoBlock, "auto-block", true, "drop and quarantine on high-confidence findings")
	f.BoolVar(&detRequireWarm, "require-warm-permit", true, "hold disposal until the Permit index is built")

	detectSettingsSet["beacon"] = func(c *apitypes.DetectionConfig) { c.BeaconEnabled = detBeaconEnabled }
	detectSettingsSet["beacon-min-sample"] = func(c *apitypes.DetectionConfig) { c.BeaconMinSample = detBeaconSample }
	detectSettingsSet["beacon-cv"] = func(c *apitypes.DetectionConfig) { c.BeaconCV = detBeaconCV }
	detectSettingsSet["beacon-min-interval"] = func(c *apitypes.DetectionConfig) { c.BeaconMinInterval = detBeaconMin }
	detectSettingsSet["beacon-max-interval"] = func(c *apitypes.DetectionConfig) { c.BeaconMaxInterval = detBeaconMax }
	detectSettingsSet["beacon-realert"] = func(c *apitypes.DetectionConfig) { c.BeaconReAlert = detBeaconReAlert }
	detectSettingsSet["beacon-realert-factor"] = func(c *apitypes.DetectionConfig) { c.BeaconReAlertFactor = detBeaconFactor }
	detectSettingsSet["dga"] = func(c *apitypes.DetectionConfig) { c.DGAEnabled = detDGAEnabled }
	detectSettingsSet["dga-min-label"] = func(c *apitypes.DetectionConfig) { c.DGAMinLabelLen = detDGALabel }
	detectSettingsSet["dga-min-entropy"] = func(c *apitypes.DetectionConfig) { c.DGAMinEntropy = detDGAEntropy }
	detectSettingsSet["tunnel-min-label"] = func(c *apitypes.DetectionConfig) { c.TunnelMinLabelLen = detTunnelLabel }
	detectSettingsSet["tunnel-min-entropy"] = func(c *apitypes.DetectionConfig) { c.TunnelMinEntropy = detTunnelEntropy }
	detectSettingsSet["subdomain-alert-at"] = func(c *apitypes.DetectionConfig) { c.SubdomainAlertAt = detSubdomainAt }
	detectSettingsSet["exfil-upload-bytes"] = func(c *apitypes.DetectionConfig) { c.ExfilUploadBytes = detExfilBytes }
	detectSettingsSet["exfil-min-ratio"] = func(c *apitypes.DetectionConfig) { c.ExfilMinRatio = detExfilRatio }
	detectSettingsSet["exfil-new-dest-hours"] = func(c *apitypes.DetectionConfig) { c.ExfilNewDestHours = detExfilNewHours }
	detectSettingsSet["query-window"] = func(c *apitypes.DetectionConfig) { c.QueryWindowSec = detQueryWindow }
	detectSettingsSet["query-nxdomain-burst"] = func(c *apitypes.DetectionConfig) { c.QueryNXBurst = detQueryNX }
	detectSettingsSet["query-parent-rate"] = func(c *apitypes.DetectionConfig) { c.QueryParentRate = detQueryRate }
	detectSettingsSet["query-odd-type-at"] = func(c *apitypes.DetectionConfig) { c.QueryOddTypeAt = detQueryOddAt }
	detectSettingsSet["auto-block"] = func(c *apitypes.DetectionConfig) { c.AutoBlock = detAutoBlock }
	detectSettingsSet["require-warm-permit"] = func(c *apitypes.DetectionConfig) { c.RequireWarmPermit = detRequireWarm }

	quarantineReleaseCmd.Flags().BoolVar(&quarantineReleaseAll, "all", false, "release everything")

	detectCmd.AddCommand(detectGetCmd, detectSetCmd)
	quarantineCmd.AddCommand(quarantineLsCmd, quarantineReleaseCmd)
}
