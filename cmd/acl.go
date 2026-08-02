package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/pkg/client"
)

// aclCmd exposes the three ACL stores. They sit on different axes and are
// deliberately not interchangeable (see the Permit ⊥ Route model):
//
//	permit   — may this destination leave the network at all? (default: no)
//	deny     — hard block, beats permit
//	no-proxy — Route axis only: egress direct. Never opens the permit gate.
var aclCmd = &cobra.Command{
	Use:   "acl",
	Short: "Permit / Deny / No-Proxy lists (Permit and Route are separate axes)",
	Long: "Permit decides whether a destination may leave the network; No-Proxy only\n" +
		"decides which way permitted traffic goes. Adding to no-proxy never grants\n" +
		"egress — that is the whole point of keeping the two axes apart.",
}

var aclLsCmd = &cobra.Command{
	Use:       "ls <permit|deny|no-proxy>",
	Short:     "Show one list",
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"permit", "deny", "no-proxy"},
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, err := client.ValidListKind(args[0])
		if err != nil {
			return err
		}
		list, err := sdk().List(kind)
		if err != nil {
			return err
		}
		return out(list, func() {
			print := func(dim, label string, vals []string) {
				if len(vals) == 0 {
					return
				}
				fmt.Printf("%s (%d):\n", label, len(vals))
				for _, v := range vals {
					if note := list.Notes[dim+":"+v]; note != "" {
						fmt.Printf("  %s  # %s\n", v, note)
					} else {
						fmt.Println("  " + v)
					}
				}
			}
			if len(list.Builtin) > 0 {
				fmt.Printf("builtin (%d, always on, read-only):\n", len(list.Builtin))
				for _, v := range list.Builtin {
					fmt.Println("  " + v)
				}
			}
			print("domain", "domains", list.Domains)
			print("ip", "ips", list.IPs)
			print("process", "processes", list.Processes)
			print("device", "devices", list.Devices)
			print("keyword", "keywords", list.Keywords)
			print("regex", "regexes", list.Regexes)
			if len(list.Domains)+len(list.IPs)+len(list.Processes)+len(list.Devices)+len(list.Keywords)+len(list.Regexes) == 0 {
				fmt.Printf("(%s list is empty)\n", args[0])
			}
		})
	},
}

var (
	aclType string
	aclNote string
)

var aclAddCmd = &cobra.Command{
	Use:   "add <permit|deny|no-proxy> <value>",
	Short: "Add an entry (hot-reloads the gateway)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, err := client.ValidListKind(args[0])
		if err != nil {
			return err
		}
		var noteArgs []string
		if cmd.Flags().Changed("note") {
			noteArgs = []string{aclNote}
		}
		list, err := sdk().AddListEntry(kind, aclType, args[1], noteArgs...)
		if err != nil {
			return err
		}
		return out(list, func() {
			if cmd.Flags().Changed("note") && aclNote != "" {
				fmt.Printf("added %s %q to %s (%s)\n", aclType, args[1], args[0], aclNote)
			} else {
				fmt.Printf("added %s %q to %s\n", aclType, args[1], args[0])
			}
		})
	},
}

var aclRmCmd = &cobra.Command{
	Use:   "rm <permit|deny|no-proxy> <value>",
	Short: "Remove an entry",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, err := client.ValidListKind(args[0])
		if err != nil {
			return err
		}
		list, err := sdk().DeleteListEntry(kind, aclType, args[1])
		if err != nil {
			return err
		}
		return out(list, func() { fmt.Printf("removed %s %q from %s\n", aclType, args[1], args[0]) })
	},
}

func init() {
	for _, c := range []*cobra.Command{aclAddCmd, aclRmCmd} {
		c.Flags().StringVar(&aclType, "type", "domain", "entry kind: domain|ip|process|device (deny also: keyword|regex)")
	}
	aclAddCmd.Flags().StringVar(&aclNote, "note", "", "optional remark (shown in ls / console; re-add with --note \"\" to clear)")
	aclCmd.AddCommand(aclLsCmd, aclAddCmd, aclRmCmd)
}
