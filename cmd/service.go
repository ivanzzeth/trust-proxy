package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/paths"
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
	svcConsole  string
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Install the gateway as a system service (launchd on macOS, systemd on Linux; needs root)",
	Long: "A system service owns the data plane instead of a desktop app: TUN gets the\n" +
		"privileges it needs, and closing a window does not drop everyone's policy.\n" +
		"`service uninstall` is the escape hatch and works from any state.",
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Write and load the system service (root)",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check privilege before anything interactive: without it a non-root run
		// asks about migrating data and only then refuses, and it cannot even see
		// the machine-wide directory (0700 root) to answer that question correctly.
		if !paths.Privileged() {
			return fmt.Errorf("installing a system service needs root: re-run with sudo")
		}
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
		program := service.Program()
		return out(map[string]any{
			"installed": installed, "running": running, "detail": detail,
			"file": service.File(), "program": program,
		}, func() {
			fmt.Printf("✓ installed %s\n", service.File())
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
	Short: "Stop and remove the system service (root)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := service.Uninstall(); err != nil {
			return err
		}
		return out(map[string]any{"installed": false}, func() {
			fmt.Println("✓ removed", service.File())
		})
	},
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Is the system service installed and running?",
	RunE: func(cmd *cobra.Command, args []string) error {
		installed, running, detail := service.Status()
		program := service.Program()
		missing := service.BinaryMissing(program)
		return out(map[string]any{
			"platform": runtime.GOOS, "installed": installed, "running": running,
			"detail": detail, "file": service.File(),
			"program": program, "program_missing": missing,
		}, func() {
			fmt.Printf("%-11s %s\n", "platform:", runtime.GOOS)
			fmt.Printf("%-11s %v (%s)\n", "installed:", installed, service.File())
			fmt.Printf("%-11s %v %s\n", "running:", running, detail)
			if program != "" {
				fmt.Printf("%-11s %s\n", "program:", program)
			}
			if missing {
				// The exact state the managed copy exists to prevent: say it out
				// loud, because launchd will keep retrying it silently forever.
				fmt.Printf("\n⚠ the program is gone — the service manager will retry it at every boot.\n")
				fmt.Printf("  fix: sudo trust-proxy service uninstall && sudo trust-proxy service install …\n")
			}
		})
	},
}

// defaultServiceData picks the data directory for a machine-wide service.
//
// The right answer is the machine-wide directory: the daemon starts at boot, as
// root, possibly before anyone logs in — a home directory may not be readable
// then (FileVault, a network home), and policy a boot daemon enforces should not
// be editable by whoever happens to be logged in.
//
// But a user who already ran `serve` by hand has all their subscriptions and
// policy in their own home, and silently starting the daemon against an empty
// machine-wide store would look like "the install wiped my config". So when there
// is existing per-user data and no machine-wide data yet, this asks — and copying
// happens only if they say yes (see migrateServiceData). Declining keeps the old
// location, which is what every install before this did.
func defaultServiceData() (string, error) {
	sys := paths.SystemData()
	if hasGatewayData(sys) {
		return sys, nil // already migrated (or installed fresh here)
	}
	usr, err := paths.UserData()
	if err != nil {
		return sys, nil //nolint:nilerr // no home to migrate from: machine-wide it is
	}
	if !hasGatewayData(usr) {
		return sys, nil
	}
	fmt.Printf("Found existing gateway data in %s.\n", usr)
	fmt.Printf("A system service runs as root at boot, so it should keep its data in %s instead.\n", sys)
	if err := confirm("Copy the existing data there now"); err != nil {
		fmt.Printf("→ keeping %s. Note the daemon runs as root and will own new files there.\n", usr)
		return usr, nil
	}
	if err := migrateServiceData(usr, sys); err != nil {
		return "", fmt.Errorf("copy %s → %s: %w", usr, sys, err)
	}
	fmt.Printf("✓ copied to %s (the original is left untouched)\n", sys)
	return sys, nil
}

// hasGatewayData reports whether a directory holds real gateway state, as opposed
// to being absent or an empty shell left by a previous run.
func hasGatewayData(dir string) bool {
	for _, name := range []string{
		"subscriptions.json", "whitelist.json", "customrules.json", "rulesets.json",
		"users.json", "profiles.json", "nodes.json", "config.json",
	} {
		if st, err := os.Stat(filepath.Join(dir, name)); err == nil && st.Size() > 0 {
			return true
		}
	}
	return false
}

// migrateServiceData copies, never moves: if the service turns out to be wrong for
// this machine the user still has a working per-user gateway to go back to.
// Existing files at the destination are left alone for the same reason.
func migrateServiceData(from, to string) error {
	if err := os.MkdirAll(to, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range entries {
		// Only the state that describes policy. cache.db is a bolt file with a
		// single-writer lock and serve.pid/log belong to another process — copying
		// those is how you get two instances fighting over one database.
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		dst := filepath.Join(to, e.Name())
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return err
		}
	}
	return nil
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
		if data, err = defaultServiceData(); err != nil {
			return c, err
		}
	}
	if c.DataDir, err = filepath.Abs(paths.ExpandHome(data)); err != nil {
		return c, err
	}
	// Same rule as serve: default to <data>/config.json, seeding it if this is a
	// fresh machine — a LaunchDaemon pointing at a config that does not exist
	// would fail at every boot.
	cfgPath, err := resolveConfig(svcConfig, c.DataDir)
	if err != nil {
		return c, err
	}
	if c.ConfigPath, err = filepath.Abs(paths.ExpandHome(cfgPath)); err != nil {
		return c, err
	}
	logPath := svcLog
	if logPath == "" {
		logPath = filepath.Join(c.DataDir, "serve.log")
	}
	if c.LogPath, err = filepath.Abs(paths.ExpandHome(logPath)); err != nil {
		return c, err
	}
	if c.ConsoleDir, err = resolveServiceConsole(); err != nil {
		return c, err
	}
	return c, nil
}

// resolveServiceConsole decides what --console the daemon gets.
//
// A service daemon runs with a working directory it did not choose, so the
// relative default (dashboard/dist) resolves to nothing: the install reports
// success and the console then serves "dashboard not built" — which is exactly
// what happened on a real machine. Three outcomes, none of them silent:
//
//   - the binary has the UI embedded  → nothing to pass, it carries its own
//   - --console given                 → made absolute and passed through
//   - neither                         → refuse, and say which two commands fix it
func resolveServiceConsole() (string, error) {
	if svcConsole == "none" {
		return "", nil // explicitly an API-only gateway; serve warns about it at startup
	}
	if svcConsole != "" {
		abs, err := filepath.Abs(paths.ExpandHome(svcConsole))
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(filepath.Join(abs, "index.html")); err != nil {
			return "", fmt.Errorf("--console %s has no index.html in it", abs)
		}
		return abs, nil
	}
	if embeddedUI != nil {
		return "", nil
	}
	return "", fmt.Errorf(
		"this binary has no console built into it, and a service cannot use the relative default:\n"+
			"  build one in:   make build-embed   (then re-run this install)\n"+
			"  or point at a built dashboard:   %s service install --console /abs/path/to/dashboard/dist\n"+
			"  or accept an API-only gateway:   --console none", os.Args[0])
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

func init() {
	for _, c := range []*cobra.Command{serviceInstallCmd, serviceUninstallCmd, serviceStatusCmd} {
		c.Flags().BoolVar(&jsonOut, "json", false, "print the raw JSON response instead of a table")
	}
	f := serviceInstallCmd.Flags()
	f.StringVarP(&svcConfig, "config", "c", "", "sing-box config path (default <data>/config.json, seeded on first run)")
	f.StringVar(&svcData, "data", "", "data directory (default: the invoking user's ~/.trust-proxy if it already has data, else the machine-wide dir)")
	f.StringVar(&svcAPIAddr, "api-addr", "127.0.0.1:21585", "backend API listen address")
	f.StringVar(&svcMode, "mode", "", "capture mode to start in: manual | system | tun (empty = the config's own)")
	f.StringVar(&svcLog, "log", "", "log file (default <data>/serve.log)")
	f.StringVar(&svcBinary, "binary", "", "trust-proxy binary to run (default: this one, symlinks resolved)")
	f.StringVar(&svcConsole, "console", "", "path to a built dashboard/dist, for a binary without an embedded console (empty = use the embedded one; \"none\" = API-only gateway)")
	f.BoolVar(&svcKeepPath, "keep-binary-path", false,
		"run the binary where it stands instead of copying it to "+service.ManagedBinary+
			" (only for a package-managed path; NEVER for one inside an .app, which breaks when the app moves)")
	f.BoolVarP(&yesToAll, "yes", "y", false, "skip the TUN confirmation")

	serviceCmd.AddCommand(serviceInstallCmd, serviceUninstallCmd, serviceStatusCmd)
}
