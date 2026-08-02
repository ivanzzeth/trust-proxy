package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// rulesCmd covers the routing/policy surface: the derived effective view, the
// ordered custom rules, the curated packs, and imported rule sets.
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Effective routing view, custom rules, policy packs and rule sets",
}

var rulesLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "Show the effective L0..L4 rule view (what the data plane will actually do)",
	RunE: func(cmd *cobra.Command, args []string) error {
		views, err := sdk().EffectiveRules()
		if err != nil {
			return err
		}
		return out(views, func() {
			fmt.Printf("%-9s %-18s %-16s %-16s %s\n", "LAYER", "SOURCE", "ACTION", "MATCHER", "VALUES")
			for _, v := range views {
				vals := truncate(strings.Join(v.Values, ","), 46)
				fmt.Printf("%-9s %-18s %-16s %-16s %s\n", v.Layer, truncate(v.Source, 18), v.Action, dash(v.Matcher), vals)
				if v.Note != "" {
					fmt.Printf("    ! %s\n", v.Note)
				}
			}
		})
	},
}

// ---- custom rules --------------------------------------------------------

var customCmd = &cobra.Command{
	Use:   "custom",
	Short: "Ordered custom rules (first match wins on the Route axis)",
}

var customLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List custom rules in priority order",
	RunE: func(cmd *cobra.Command, args []string) error {
		rules, err := sdk().CustomRules()
		if err != nil {
			return err
		}
		return out(rules, func() {
			if len(rules) == 0 {
				fmt.Println("(no custom rules)")
				return
			}
			fmt.Printf("%-4s %-14s %-14s %-30s %-8s %-7s %-12s %s\n", "#", "ID", "MATCH", "VALUE", "EGRESS", "PERMIT", "PACK", "ON")
			for i, r := range rules {
				permit := "derive"
				if r.Permit != nil {
					permit = yesNo(*r.Permit)
				}
				eg := r.Egress
				if eg == "" {
					eg = r.Action
				}
				fmt.Printf("%-4d %-14s %-14s %-30s %-8s %-7s %-12s %s\n",
					i+1, r.ID, r.Match, truncate(r.Value, 30), dash(eg), permit, dash(r.Pack), yesNo(r.Enabled))
			}
		})
	},
}

var (
	customMatch  string
	customEgress string
	customPermit bool
	customNode   string
	customPack   string
)

var customAddCmd = &cobra.Command{
	Use:   "add <value>",
	Short: "Add a custom rule",
	Long: "Permit and Egress are orthogonal: --permit grants the destination the right\n" +
		"to leave the network, --egress only picks which way it goes. A rule with an\n" +
		"egress but no --permit routes traffic that some other rule already permitted.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		permit := customPermit
		r := apitypes.CustomRule{
			Match: customMatch, Value: args[0], Egress: customEgress,
			Node: customNode, Pack: customPack, Enabled: true,
			Permit: &permit,
		}
		rules, err := sdk().AddCustomRule(r)
		if err != nil {
			return err
		}
		return out(rules, func() {
			// the store derives the id, so report the rule as it came back
			for _, got := range rules {
				if got.Value == r.Value && got.Match == r.Match {
					fmt.Printf("added %s: %s %q egress=%s permit=%v\n", got.ID, got.Match, got.Value, dash(got.Egress), permit)
					return
				}
			}
			fmt.Printf("added %s %q (%d rule(s) now)\n", r.Match, r.Value, len(rules))
		})
	},
}

var customRmCmd = &cobra.Command{
	Use:   "rm <id>",
	Short: "Delete a custom rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().DeleteCustomRule(args[0]); err != nil {
			return err
		}
		fmt.Println("removed", args[0])
		return nil
	},
}

var customEnable bool

var customToggleCmd = &cobra.Command{
	Use:   "toggle <id>",
	Short: "Enable/disable a custom rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rules, err := sdk().PatchCustomRule(args[0], apitypes.PatchCustomRuleRequest{Enabled: &customEnable})
		if err != nil {
			return err
		}
		return out(rules, func() { fmt.Printf("%s enabled=%v\n", args[0], customEnable) })
	},
}

var customMoveCmd = &cobra.Command{
	Use:       "move <id> <up|down|top>",
	Short:     "Change a rule's priority (first match wins; top = index 0, not a pin)",
	Args:      cobra.ExactArgs(2),
	ValidArgs: []string{"up", "down", "top"},
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			rules []apitypes.CustomRule
			err   error
		)
		switch args[1] {
		case "up":
			rules, err = sdk().MoveCustomRule(args[0], -1)
		case "down":
			rules, err = sdk().MoveCustomRule(args[0], 1)
		case "top":
			rules, err = sdk().MoveCustomRuleTop(args[0])
		default:
			return fmt.Errorf("direction must be up, down, or top")
		}
		if err != nil {
			return err
		}
		return out(rules, func() { fmt.Printf("moved %s %s\n", args[0], args[1]) })
	},
}

// ---- policy packs --------------------------------------------------------

var packsCmd = &cobra.Command{
	Use:   "packs",
	Short: "Curated policy packs (Claude / OpenAI / China-direct / …)",
}

var packsLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List the pack catalog",
	RunE: func(cmd *cobra.Command, args []string) error {
		packs, err := sdk().PackCatalog()
		if err != nil {
			return err
		}
		return out(packs, func() {
			fmt.Printf("%-18s %-10s %-8s %s\n", "NAME", "EXIT", "SETS", "DESCRIPTION")
			for _, p := range packs {
				fmt.Printf("%-18s %-10s %-8d %s\n", p.Name, dash(p.Exit), len(p.RuleSets), truncate(p.Description, 60))
				if p.Warning != "" {
					fmt.Printf("    ! %s\n", p.Warning)
				}
			}
		})
	},
}

var packsApplyCmd = &cobra.Command{
	Use:   "apply <name>",
	Short: "Import a pack (idempotent; re-apply overwrites its rules)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := sdk().ApplyPack(args[0])
		if err != nil {
			return err
		}
		return out(res, func() {
			fmt.Printf("applied pack %q: %d rule(s), %d rule set(s)\n", args[0], len(res.Rules), len(res.RuleSets))
		})
	},
}

var packsToggleCmd = &cobra.Command{
	Use:   "toggle <name>",
	Short: "Enable/disable every rule of a pack",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rules, err := sdk().PatchPack(args[0], customEnable)
		if err != nil {
			return err
		}
		return out(rules, func() { fmt.Printf("pack %q enabled=%v\n", args[0], customEnable) })
	},
}

var packsRmCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Remove a pack's rules (and subtract its rule-set roles)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().DeletePack(args[0]); err != nil {
			return err
		}
		fmt.Println("removed pack", args[0])
		return nil
	},
}

// ---- rule sets -----------------------------------------------------------

var setsCmd = &cobra.Command{
	Use:   "sets",
	Short: "Imported sing-box rule sets and their Permit/Route/Deny roles",
}

var setsLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List imported rule sets",
	RunE: func(cmd *cobra.Command, args []string) error {
		sets, err := sdk().RuleSets()
		if err != nil {
			return err
		}
		return out(sets, func() {
			if len(sets) == 0 {
				fmt.Println("(no rule sets)")
				return
			}
			fmt.Printf("%-22s %-22s %-8s %-6s %s\n", "TAG", "ROLE", "TYPE", "ON", "NAME")
			for _, s := range sets {
				fmt.Printf("%-22s %-22s %-8s %-6s %s\n", s.Tag, dash(s.Role), s.Type, yesNo(s.Enabled), truncate(s.Name, 34))
			}
		})
	},
}

var setsCatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "List the public rule sets available for one-click import",
	RunE: func(cmd *cobra.Command, args []string) error {
		entries, err := sdk().RuleSetCatalog()
		if err != nil {
			return err
		}
		return out(entries, func() {
			fmt.Printf("%-22s %-22s %-8s %s\n", "TAG", "SUGGESTED ROLE", "FORMAT", "NAME")
			for _, e := range entries {
				fmt.Printf("%-22s %-22s %-8s %s\n", e.Tag, dash(e.SuggestedRole), e.Format, truncate(e.Name, 40))
			}
		})
	},
}

var (
	setsRole   string
	setsURL    string
	setsPath   string
	setsFormat string
	setsMirror bool
)

var setsAddCmd = &cobra.Command{
	Use:   "add <tag>",
	Short: "Import a rule set (from the catalog by tag, or --url/--path)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		req := apitypes.AddRuleSetRequest{Role: setsRole, Mirror: setsMirror}
		switch {
		case setsURL != "":
			req.Tag, req.Type, req.URL, req.Format = args[0], "remote", setsURL, setsFormat
		case setsPath != "":
			req.Tag, req.Type, req.Path, req.Format = args[0], "local", setsPath, setsFormat
		default:
			req.CatalogTag = args[0] // curated catalog import
		}
		sets, err := sdk().AddRuleSet(req)
		if err != nil {
			return err
		}
		return out(sets, func() { fmt.Printf("imported %q (%d rule set(s) now)\n", args[0], len(sets)) })
	},
}

var setsRoleCmd = &cobra.Command{
	Use:   "role <tag> <role>",
	Short: "Set a rule set's role: deny|permit|route-direct|route-proxy|permit+route-direct|permit+route-proxy",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		role := args[1]
		sets, err := sdk().PatchRuleSet(args[0], apitypes.PatchRuleSetRequest{Role: &role})
		if err != nil {
			return err
		}
		return out(sets, func() { fmt.Printf("%s role=%s\n", args[0], role) })
	},
}

var setsToggleCmd = &cobra.Command{
	Use:   "toggle <tag>",
	Short: "Enable/disable a rule set",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sets, err := sdk().PatchRuleSet(args[0], apitypes.PatchRuleSetRequest{Enabled: &customEnable})
		if err != nil {
			return err
		}
		return out(sets, func() { fmt.Printf("%s enabled=%v\n", args[0], customEnable) })
	},
}

var setsRmCmd = &cobra.Command{
	Use:   "rm <tag>",
	Short: "Remove a rule set",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sdk().DeleteRuleSet(args[0]); err != nil {
			return err
		}
		fmt.Println("removed", args[0])
		return nil
	},
}

var setsShowCmd = &cobra.Command{
	Use:   "show <tag>",
	Short: "Show a rule set's decoded contents",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body, err := sdk().RuleSetRules(args[0])
		if err != nil {
			return err
		}
		return emit(body) // contents are a list; JSON is the honest rendering
	},
}

func init() {
	customAddCmd.Flags().StringVar(&customMatch, "match", "domain_suffix", "matcher: domain|domain_suffix|keyword|regex|ip_cidr")
	customAddCmd.Flags().StringVar(&customEgress, "egress", "", "egress: direct|proxy|block|node (empty = Route axis untouched)")
	customAddCmd.Flags().BoolVar(&customPermit, "permit", false, "also grant Permit (allow it to leave the network)")
	customAddCmd.Flags().StringVar(&customNode, "node", "", "target outbound tag (required with --egress node)")
	customAddCmd.Flags().StringVar(&customPack, "pack", "", "tag the rule as part of a named pack")
	for _, c := range []*cobra.Command{customToggleCmd, packsToggleCmd, setsToggleCmd} {
		c.Flags().BoolVar(&customEnable, "enabled", true, "target state")
	}
	setsAddCmd.Flags().StringVar(&setsRole, "role", "", "role on import (default: the catalog's suggestion)")
	setsAddCmd.Flags().StringVar(&setsURL, "url", "", "import a remote rule set from this URL instead of the catalog")
	setsAddCmd.Flags().StringVar(&setsPath, "path", "", "import a local rule-set file")
	setsAddCmd.Flags().StringVar(&setsFormat, "format", "binary", "rule-set format: binary (.srs) | source (.json)")
	setsAddCmd.Flags().BoolVar(&setsMirror, "mirror", false, "use the catalog's CDN mirror URL")

	customCmd.AddCommand(customLsCmd, customAddCmd, customRmCmd, customToggleCmd, customMoveCmd)
	packsCmd.AddCommand(packsLsCmd, packsApplyCmd, packsToggleCmd, packsRmCmd)
	setsCmd.AddCommand(setsLsCmd, setsCatalogCmd, setsAddCmd, setsRoleCmd, setsToggleCmd, setsRmCmd, setsShowCmd)
	rulesCmd.AddCommand(rulesLsCmd, customCmd, packsCmd, setsCmd)
}
