package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/service"
)

// `service` installs the gateway as a system daemon. It lives in the CLI, not in
// the desktop shell, for the usual reason: the shell must not be the only way to
// do something. The shell just runs these commands with an admin prompt.
//
// Local by design (no --api-addr): this touches the machine, not a running
// gateway — and it has to work when no gateway is running at all.

var (
	svcConfig   string
	svcData     string
	svcAPIAddr  string
	svcMode     string
	svcLog      string
	svcBinary   string
	svcKeepPath bool
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Install the gateway as a system service (macOS launchd; needs root)",
	Long: "A system service owns the data plane instead of a desktop app: TUN gets the\n" +
		"privileges it needs, and closing a window does not drop everyone's policy.\n" +
		"`service uninstall` is the escape hatch and works from any state.",
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Write and load the LaunchDaemon (root)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := serviceConfig()
		if err != nil {
			return err
		}
		c.KeepBinaryPath = svcKeepPath
		if svcMode == "tun" {
			// A boot-time TUN daemon captures everything on this machine from the
			// next restart onward; that deserves a yes.
			if err := confirm("Install with TUN capture enabled? The service starts at boot and captures all traffic"); err != nil {
				return err
			}
		}
		if err := service.Install(c); err != nil {
			return err
		}
		installed, running, detail := service.Status()
		program := service.ProgramFromPlist()
		return out(map[string]any{
			"installed": installed, "running": running, "detail": detail,
			"plist": service.PlistPath, "program": program,
		}, func() {
			fmt.Printf("✓ installed %s\n", service.PlistPath)
			fmt.Printf("  program: %s\n", program)
			fmt.Printf("  serve -c %s --data %s --api-addr %s", c.ConfigPath, c.DataDir, c.APIAddr)
			if c.Mode != "" {
				fmt.Printf(" --mode %s", c.Mode)
			}
			fmt.Printf("\n  logs: %s\n", c.LogPath)
			fmt.Printf("  remove it with: sudo trust-proxy service uninstall\n")
		})
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove the LaunchDaemon (root)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := service.Uninstall(); err != nil {
			return err
		}
		return out(map[string]any{"installed": false}, func() {
			fmt.Println("✓ removed", service.PlistPath)
		})
	},
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Is the system service installed and running?",
	RunE: func(cmd *cobra.Command, args []string) error {
		installed, running, detail := service.Status()
		program := service.ProgramFromPlist()
		missing := service.BinaryMissing(program)
		return out(map[string]any{
			"platform": runtime.GOOS, "installed": installed, "running": running,
			"detail": detail, "plist": service.PlistPath,
			"program": program, "program_missing": missing,
		}, func() {
			fmt.Printf("%-11s %s\n", "platform:", runtime.GOOS)
			fmt.Printf("%-11s %v (%s)\n", "installed:", installed, service.PlistPath)
			fmt.Printf("%-11s %v %s\n", "running:", running, detail)
			if program != "" {
				fmt.Printf("%-11s %s\n", "program:", program)
			}
			if missing {
				// The exact state the managed copy exists to prevent: say it out
				// loud, because launchd will keep retrying it silently forever.
				fmt.Printf("\n⚠ the program is gone — launchd will retry it at every boot.\n")
				fmt.Printf("  fix: sudo trust-proxy service uninstall && sudo trust-proxy service install …\n")
			}
		})
	},
}

// serviceConfig fills in the defaults a desktop install wants: absolute paths
// (launchd resolves nothing) and this very binary as the program to run.
func serviceConfig() (service.Config, error) {
	c := service.Config{APIAddr: svcAPIAddr, Mode: svcMode}
	var err error
	if c.Binary, err = absOrSelf(svcBinary); err != nil {
		return c, err
	}
	// Resolved after the data dir below, since the default lives inside it.

	data := svcData
	if data == "" {
		// Same default as serve, but resolved here: a daemon running as root must
		// not silently land in /var/root/.trust-proxy while the user's data sits
		// in their home directory.
		home, err := os.UserHomeDir()
		if err != nil {
			return c, err
		}
		data = filepath.Join(home, ".trust-proxy")
	}
	if c.DataDir, err = filepath.Abs(expandHome(data)); err != nil {
		return c, err
	}
	// Same rule as serve: default to <data>/config.json, seeding it if this is a
	// fresh machine — a LaunchDaemon pointing at a config that does not exist
	// would fail at every boot.
	cfgPath, err := resolveConfig(svcConfig, c.DataDir)
	if err != nil {
		return c, err
	}
	if c.ConfigPath, err = filepath.Abs(expandHome(cfgPath)); err != nil {
		return c, err
	}
	logPath := svcLog
	if logPath == "" {
		logPath = filepath.Join(c.DataDir, "serve.log")
	}
	if c.LogPath, err = filepath.Abs(expandHome(logPath)); err != nil {
		return c, err
	}
	return c, nil
}

// absOrSelf resolves an explicit --binary, or this executable's real path.
func absOrSelf(p string) (string, error) {
	if p != "" {
		return filepath.Abs(p)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	// Resolve symlinks: a Homebrew-style link would break the moment it is
	// re-pointed, and launchd would keep running the old target.
	return filepath.EvalSymlinks(exe)
}

func expandHome(p string) string {
	if p == "~" || len(p) > 1 && p[:2] == "~/" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

func init() {
	for _, c := range []*cobra.Command{serviceInstallCmd, serviceUninstallCmd, serviceStatusCmd} {
		c.Flags().BoolVar(&jsonOut, "json", false, "print the raw JSON response instead of a table")
	}
	f := serviceInstallCmd.Flags()
	f.StringVarP(&svcConfig, "config", "c", "", "sing-box config path (default <data>/config.json, seeded on first run)")
	f.StringVar(&svcData, "data", "", "data directory (default ~/.trust-proxy of the invoking user)")
	f.StringVar(&svcAPIAddr, "api-addr", "127.0.0.1:9096", "backend API listen address")
	f.StringVar(&svcMode, "mode", "", "capture mode to start in: manual | system | tun (empty = the config's own)")
	f.StringVar(&svcLog, "log", "", "log file (default <data>/serve.log)")
	f.StringVar(&svcBinary, "binary", "", "trust-proxy binary to run (default: this one, symlinks resolved)")
	f.BoolVar(&svcKeepPath, "keep-binary-path", false,
		"run the binary where it stands instead of copying it to "+service.ManagedBinary+
			" (only for a package-managed path; NEVER for one inside an .app, which breaks when the app moves)")
	f.BoolVarP(&yesToAll, "yes", "y", false, "skip the TUN confirmation")

	serviceCmd.AddCommand(serviceInstallCmd, serviceUninstallCmd, serviceStatusCmd)
}
