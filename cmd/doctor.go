package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/doctor"
	"github.com/ivanzzeth/trust-proxy/internal/paths"
)

var (
	doctorAutoInstall bool
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Dependency doctor (nftables, etc.) and optional auto-install",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Default: show nftables doctor for now.
		rep := doctor.DetectNftables(context.Background(), paths.Privileged())
		return out(rep, func() {
			fmt.Printf("nftables:\n")
			fmt.Printf("  supported:              %s\n", yesNo(rep.Supported))
			fmt.Printf("  nft binary:             %s\n", yesNo(rep.HasNftBinary))
			fmt.Printf("  usable (nft list):     %s\n", yesNo(rep.Usable))
			fmt.Printf("  auto-install supported: %s\n", yesNo(rep.AutoInstallSupported))
			if len(rep.SuggestedPackages) > 0 {
				fmt.Printf("  suggested packages:    %v\n", rep.SuggestedPackages)
			}
			if rep.SuggestedInstallCmd != "" {
				fmt.Printf("  suggested install cmd: %s\n", rep.SuggestedInstallCmd)
			}
			for _, e := range rep.Errors {
				fmt.Printf("  error: %s\n", e)
			}
		})
	},
}

var doctorNftablesCmd = &cobra.Command{
	Use:   "nftables",
	Short: "Check nftables support and optionally install nftables userspace package",
	RunE: func(cmd *cobra.Command, args []string) error {
		rep := doctor.DetectNftables(context.Background(), paths.Privileged())

		if doctorAutoInstall {
			if !rep.AutoInstallSupported {
				return fmt.Errorf("auto-install not available (root required and a known package manager must exist)")
			}
			if !rep.Usable || !rep.HasNftBinary {
				if !yesToAll {
					if err := confirm("Install nftables userspace package?"); err != nil {
						return err
					}
				}
				rep2, err := doctor.InstallNftables(context.Background(), doctor.InstallNftablesRequest{Yes: true})
				if err != nil {
					// Still print the last report so the user sees what happened.
					_ = out(rep2, func() {})
					return err
				}
				rep = rep2
			}
		}

		return out(rep, func() {
			fmt.Printf("nftables:\n")
			fmt.Printf("  supported:               %s\n", yesNo(rep.Supported))
			fmt.Printf("  nft binary:              %s\n", yesNo(rep.HasNftBinary))
			fmt.Printf("  usable (nft list):      %s\n", yesNo(rep.Usable))
			fmt.Printf("  auto-install supported: %s\n", yesNo(rep.AutoInstallSupported))
			if rep.SuggestedInstallCmd != "" {
				fmt.Printf("  suggested install cmd:  %s\n", rep.SuggestedInstallCmd)
			}
			if len(rep.Errors) > 0 {
				fmt.Printf("  errors: %v\n", rep.Errors)
			}
		})
	},
}

func init() {
	doctorCmd.AddCommand(doctorNftablesCmd)
	doctorNftablesCmd.Flags().BoolVar(&doctorAutoInstall, "auto-install", false, "If missing, attempt to install nftables userspace package (best-effort)")
	doctorNftablesCmd.Flags().BoolVar(&jsonOut, "json", false, "print the raw JSON response instead of a table")
	doctorNftablesCmd.Flags().BoolVarP(&yesToAll, "yes", "y", false, "skip the confirmation prompt")
}
