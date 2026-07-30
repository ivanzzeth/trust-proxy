package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/credentials"
	"github.com/ivanzzeth/trust-proxy/internal/paths"
	"github.com/ivanzzeth/trust-proxy/internal/service"
	"github.com/ivanzzeth/trust-proxy/pkg/client"
)

// `install` is the only way a gateway gets onto a machine.
//
// One shape, everywhere: root/SYSTEM, machine-wide data directory, owned by the
// platform's service manager, started at boot. The per-user gateway this used to
// also support is gone — it could not do TUN, it died with whatever window
// started it, and running it under sudo left a root-owned directory in a home
// that the unprivileged desktop app then could not write.
//
// So this command has to finish the job, not leave a half-set-up machine:
//
//	privilege check → nobody else on the port → resolve config/data/console
//	→ adopt the old per-user data once → copy the binary somewhere stable
//	→ register + start the service → wait for it to answer
//	→ claim it and hand the API key to the human who authorized this
//
// Local by design (no --api-addr pointing elsewhere): this touches *this*
// machine, and has to work when no gateway is running at all.

var (
	svcConfig   string
	svcData     string
	svcAPIAddr  string
	svcMode     string
	svcLog      string
	svcBinary   string
	svcKeepPath bool
	svcConsole  string
	svcTakeover bool
	svcClaimFor string
	svcNoClaim  bool
)

const installLong = "Installs the gateway as a system service: it runs as root, keeps its data in\n" +
	"the machine-wide directory, starts at boot and restarts if it dies. That is the\n" +
	"only supported shape — TUN needs root, and policy a boot-time daemon enforces\n" +
	"must not be editable by whoever happens to be logged in.\n\n" +
	"It also claims the gateway for you on first install: the first admin account is\n" +
	"created and its API key is written to your own home directory, so the CLI works\n" +
	"immediately afterwards without another step.\n\n" +
	"`uninstall` is the escape hatch and works from any half-installed state."

func newInstallCmd(hidden bool) *cobra.Command {
	c := &cobra.Command{
		Use:    "install",
		Short:  "Install the gateway as a system service and claim it (root)",
		Long:   installLong,
		Hidden: hidden,
		RunE:   func(cmd *cobra.Command, args []string) error { return runInstall() },
	}
	f := c.Flags()
	f.StringVarP(&svcConfig, "config", "c", "", "sing-box config path (default <data>/config.json, seeded on first run)")
	f.StringVar(&svcData, "data", "", "data directory override (default: the machine-wide one, "+paths.Data()+")")
	f.StringVar(&svcAPIAddr, "api-addr", "127.0.0.1:21585", "backend API listen address")
	f.StringVar(&svcMode, "mode", "", "capture mode to start in: manual | system | tun (empty = leave this machine's current setting, so upgrading preserves TUN; can also be switched later from the console)")
	f.StringVar(&svcLog, "log", "", "log file (default <data>/serve.log)")
	f.StringVar(&svcBinary, "binary", "", "trust-proxy binary to run (default: this one, symlinks resolved)")
	f.StringVar(&svcConsole, "console", "", "path to a built dashboard/dist, for a binary without an embedded console (empty = use the embedded one; \"none\" = API-only gateway)")
	f.BoolVar(&svcKeepPath, "keep-binary-path", false,
		"run the binary where it stands instead of copying it to "+service.ManagedBinary+
			" (only for a package-managed path; NEVER for one inside an .app, which breaks when the app moves)")
	f.BoolVarP(&yesToAll, "yes", "y", false, "skip the TUN confirmation")
	f.BoolVar(&svcTakeover, "takeover", false,
		"stop a gateway that is already using the API port instead of refusing (the desktop app uses this)")
	f.StringVar(&svcClaimFor, "claim-for", "",
		"the account to create the first admin for and hand the API key to (default: whoever invoked this, via SUDO_USER)")
	f.BoolVar(&svcNoClaim, "no-claim", false,
		"install without creating the first admin (leaves the gateway unclaimed; it stays open on loopback until someone claims it)")
	f.BoolVar(&jsonOut, "json", false, "print the raw JSON response instead of a table")
	return c
}

func newUninstallCmd(hidden bool) *cobra.Command {
	c := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the system service (root)",
		Long: "Removes the service, its managed copy of the binary, and nothing else.\n" +
			"Your policy, subscriptions and accounts stay in " + paths.Data() + " —\n" +
			"uninstalling a service must never be how somebody loses their configuration.",
		Hidden: hidden,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := service.Uninstall(); err != nil {
				return err
			}
			return out(map[string]any{"installed": false}, func() {
				fmt.Println("✓ removed", service.File())
				fmt.Printf("  your configuration is still in %s\n", paths.Data())
			})
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "print the raw JSON response instead of a table")
	return c
}

var serviceCmd = &cobra.Command{
	Use:    "service",
	Short:  "Older spelling of `install` / `uninstall` / `status`",
	Hidden: true,
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Is the system service installed and running?",
	RunE: func(cmd *cobra.Command, args []string) error {
		installed, running, detail := service.Status()
		program := service.Program()
		missing := service.BinaryMissing(program)
		unreadable := service.DefinitionUnreadable()
		return out(map[string]any{
			"platform": runtime.GOOS, "installed": installed, "running": running,
			"detail": detail, "file": service.File(),
			"program": program, "program_missing": missing,
			"definition_unreadable": unreadable,
			"data_dir":              paths.Data(),
		}, func() {
			fmt.Printf("%-11s %s\n", "platform:", runtime.GOOS)
			fmt.Printf("%-11s %v (%s)\n", "installed:", installed, service.File())
			fmt.Printf("%-11s %v %s\n", "running:", running, detail)
			if program != "" {
				fmt.Printf("%-11s %s\n", "program:", program)
			}
			fmt.Printf("%-11s %s\n", "data:", paths.Data())
			if unreadable {
				// Say it, rather than printing an empty program and letting the
				// reader conclude there is nothing to check: every staleness check
				// downstream of this field is disabled while it stays unreadable.
				fmt.Printf("\n⚠ the service definition is not readable, so we cannot tell which binary it runs.\n")
				fmt.Printf("  (installed before the mode fix; re-run `sudo trust-proxy install` to heal it)\n")
			}
			if missing {
				// The exact state the managed copy exists to prevent: say it out
				// loud, because the service manager will keep retrying it silently.
				fmt.Printf("\n⚠ the program is gone — the service manager will retry it at every boot.\n")
				fmt.Printf("  fix: sudo trust-proxy uninstall && sudo trust-proxy install\n")
			}
		})
	},
}

// runInstall is the whole install, in the order that keeps a failure harmless.
func runInstall() error {
	// Privilege first, before anything interactive or with a side effect: without
	// it we cannot even see the machine-wide directory (0700 root) to reason about
	// it, and refusing halfway leaves a half-done install behind.
	if !paths.Privileged() {
		return fmt.Errorf("installing a system service needs root: re-run with sudo")
	}
	// install seeds config.json and mode.json into the machine-wide directory, so it
	// creates files there too — same reason as serve.
	tightenUmask()
	// Then the port, still before any side effect. Something already answering
	// means the service would start, fail to bind, and be retried at every boot —
	// while the machine looks fine, because the *other* gateway is answering.
	//
	// Unless the thing answering is our own installed service. Re-running install
	// is how you upgrade the binary or change the mode, and `service.Install`
	// already stops the old job before replacing its unit — refusing here made the
	// most ordinary maintenance command fail on the machine it was maintaining,
	// and `--takeover` could not rescue it either, because a service-managed
	// gateway has no pid file to signal.
	if who, ours := portOccupant(svcAPIAddr); who != "" && !ours && !svcTakeover {
		return portConflictError(svcAPIAddr, who, "")
	}

	owner, err := claimOwner()
	if err != nil {
		return err
	}
	// Adopt *before* resolving the config, not after.
	//
	// Resolving seeds <data>/config.json when there is none, which makes the
	// destination look like an existing install to the adoption check — so nothing
	// was ever carried over, silently. Measured in the Linux e2e: the whitelist
	// from a pre-refactor per-user install simply did not arrive. Going first also
	// means a config the user had edited becomes the config the service runs,
	// rather than being shadowed by a freshly seeded default.
	dataDir, err := serviceDataDir()
	if err != nil {
		return err
	}
	adopted := adoptLegacyData(owner, dataDir)

	c, err := serviceConfig()
	if err != nil {
		return err
	}
	// Re-check with the resolved address: it may differ from the flag, and
	// something may have taken the port while we were resolving.
	if who, ours := portOccupant(c.APIAddr); who != "" && !ours {
		if !svcTakeover {
			return portConflictError(c.APIAddr, who, c.DataDir)
		}
		// --takeover: the caller has said the service should be the gateway, so the
		// one in the way gets stopped. The desktop app always asks for this —
		// clicking "set up" cannot reasonably mean "and also leave the other
		// gateway running". Look in the service's own directory and in the legacy
		// per-user one, which is where a hand-started gateway's pid file is.
		if err := stopGatewayOn(c.APIAddr, c.DataDir, paths.LegacyUserData(owner.Home)); err != nil {
			return err
		}
	}
	c.KeepBinaryPath = svcKeepPath
	if svcMode == "tun" {
		// A boot-time TUN daemon captures everything on this machine from the next
		// restart onward; that deserves a yes.
		if err := confirm("Install with TUN capture enabled? The service starts at boot and captures all traffic"); err != nil {
			return err
		}
	}
	// The mode goes in the store, not in the service definition's arguments.
	//
	// This is what makes a bare re-install — the documented upgrade path, and what
	// the desktop Update button runs — preserve TUN instead of silently turning it
	// off. No --mode means "leave whatever this machine is set to", which is now a
	// statement the code can actually honour; while the mode lived in the plist's
	// argument list, rewriting that list dropped it.
	//
	// After the refusals and before the service starts: seeding it here means the
	// daemon reads the intended mode on its very first boot, and an install that
	// gets rejected above has not written anything.
	mode, err := seedMode(c.DataDir, svcMode)
	if err != nil {
		return err
	}
	if err := service.Install(c); err != nil {
		return err
	}

	installed, running, detail := service.Status()
	program := service.Program()
	res := map[string]any{
		"installed": installed, "running": running, "detail": detail,
		"file": service.File(), "program": program,
		"data_dir": c.DataDir, "api_addr": c.APIAddr, "mode": mode,
		"console_url": "http://" + c.APIAddr + "/",
		"adopted":     adopted,
	}

	// The service is registered; now make it usable. A failure past this point is
	// reported but does not undo the install — a running gateway you have to claim
	// by hand beats no gateway at all.
	claimed, claimErr := claimGateway(c.APIAddr, owner)
	res["claim"] = claimed
	if claimErr != nil {
		res["claim_error"] = claimErr.Error()
	}

	return out(res, func() {
		fmt.Printf("✓ installed %s\n", service.File())
		fmt.Printf("  program: %s\n", program)
		fmt.Printf("  data:    %s\n", c.DataDir)
		fmt.Printf("  logs:    %s\n", c.LogPath)
		fmt.Printf("  mode:    %s\n", mode)
		if adopted > 0 {
			fmt.Printf("  adopted %d file(s) from the old per-user directory\n", adopted)
		}
		switch {
		case claimErr != nil:
			fmt.Printf("\n⚠ the gateway is running but could not be claimed: %v\n", claimErr)
			fmt.Printf("  claim it yourself:  trust-proxy auth bootstrap <name>\n")
		case claimed.Created:
			fmt.Printf("\n✓ claimed as %q; the API key is in %s\n", claimed.Username, claimed.CredentialsPath)
			fmt.Printf("  the CLI works now — try:  trust-proxy status\n")
			fmt.Printf("  set a console password when you want to log in from a browser elsewhere:\n")
			fmt.Printf("      trust-proxy user passwd %s\n", claimed.Username)
		case claimed.AlreadyClaimed:
			fmt.Printf("\n  already claimed — log in with your existing account:  trust-proxy auth login <name>\n")
		}
		fmt.Printf("\n  console: http://%s/\n", c.APIAddr)
		fmt.Printf("  remove it with: sudo trust-proxy uninstall\n")
	})
}

// ---- claiming -------------------------------------------------------------

// claimResult is what the install did about the first account.
type claimResult struct {
	Created         bool   `json:"created"`
	AlreadyClaimed  bool   `json:"already_claimed"`
	Skipped         bool   `json:"skipped"`
	Username        string `json:"username,omitempty"`
	UserID          string `json:"user_id,omitempty"`
	CredentialsPath string `json:"credentials_path,omitempty"`
	GatewayID       string `json:"gateway_id,omitempty"`
}

// claimOwner is the human this install is being done for.
//
// Under sudo that is SUDO_USER, not root — a credential dropped in /var/root is
// a credential nobody at the keyboard will ever find. The desktop shell passes
// --claim-for explicitly, because the authorization prompt it used does not
// necessarily set SUDO_USER.
func claimOwner() (paths.Owner, error) {
	if svcClaimFor != "" {
		return paths.LookupOwner(svcClaimFor)
	}
	return paths.InvokingOwner()
}

// claimGateway creates the first admin and leaves its API key where the owner can
// read it, so the CLI works the moment install returns.
//
// Everything goes through the API, like every other write to the registry: the
// running gateway is the only writer of users.json, and a second one would leave
// it with a stale copy. On loopback an unclaimed gateway accepts this without a
// credential — that is what makes a fresh install claimable at all.
func claimGateway(apiAddr string, owner paths.Owner) (claimResult, error) {
	if svcNoClaim {
		return claimResult{Skipped: true}, nil
	}
	if err := waitForAPI(apiAddr, 30*time.Second); err != nil {
		return claimResult{}, err
	}
	c := client.New(client.Options{APIBaseURL: apiAddr})
	st, err := c.AuthState()
	if err != nil {
		return claimResult{}, fmt.Errorf("ask the gateway whether it needs claiming: %w", err)
	}
	if !st.NeedsBootstrap {
		// Someone already owns this gateway (a reinstall, or adopted data that came
		// with accounts). Minting a key for them without their password is not ours
		// to do, and silently overwriting their credential file would be worse.
		return claimResult{AlreadyClaimed: true, GatewayID: st.GatewayID}, nil
	}
	name := accountName(owner.Username)
	// A random password nobody has to remember: the working credential is the API
	// key below, and the console arrives via a session. Someone who wants to log in
	// from another browser sets one with `user passwd`. Generating a weak default,
	// or printing one for the desktop shell to swallow, would be worse than either.
	pw, err := randomPassword()
	if err != nil {
		return claimResult{}, err
	}
	sess, err := c.BootstrapWithGeneratedPassword(name, pw, "")
	if err != nil {
		return claimResult{}, fmt.Errorf("create the first admin: %w", err)
	}
	created, err := c.CreateAPIKey(sess.User.ID, "installed-for-"+name, 0)
	if err != nil {
		return claimResult{Created: true, Username: name, UserID: sess.User.ID},
			fmt.Errorf("admin %q was created, but minting its API key failed: %w", name, err)
	}
	path, err := credentials.PutFor(owner, apiAddr, credentials.Entry{
		GatewayID: st.GatewayID,
		Key:       created.Key,
		KeyID:     created.ID,
		UserID:    sess.User.ID,
		Username:  name,
	})
	if err != nil {
		return claimResult{Created: true, Username: name, UserID: sess.User.ID},
			fmt.Errorf("admin %q was created, but its key could not be saved: %w", name, err)
	}
	return claimResult{
		Created: true, Username: name, UserID: sess.User.ID,
		CredentialsPath: path, GatewayID: st.GatewayID,
	}, nil
}

// accountName turns a system username into one the registry will accept.
//
// Windows hands us `DOMAIN\person`, and macOS accounts can carry characters the
// registry rejects. Failing the whole install over the shape of somebody's login
// name would be absurd, so it is trimmed to fit and, if nothing usable is left,
// becomes "admin".
func accountName(system string) string {
	if i := strings.LastIndexAny(system, `\/`); i >= 0 {
		system = system[i+1:]
	}
	var b strings.Builder
	for _, r := range system {
		switch {
		case r == '-' || r == '_' || r == '.' || r == '@',
			r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if len(name) > 32 {
		name = name[:32]
	}
	if len(name) < 2 {
		return "admin"
	}
	return name
}

func randomPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// waitForAPI blocks until the freshly installed service answers. Without it the
// claim races the daemon's start and fails on a gateway that was about to be
// perfectly fine.
func waitForAPI(addr string, within time.Duration) error {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if gatewayOn(addr) != "" {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("the service was installed but its API never answered on %s — "+
		"check `trust-proxy service status` and the log", addr)
}

// ---- who is on the port ---------------------------------------------------

// gatewayOn reports whether anything answers /api/health at addr.
func gatewayOn(addr string) string {
	who, _ := portOccupant(addr)
	return who
}

// portOccupant describes who holds the API port, and whether it is our own
// installed service.
//
// The distinction decides everything downstream: a stranger on the port means
// the service we are about to install could never bind, and refusing is the only
// honest answer. Our own service means this is a re-install, and replacing it is
// the whole job — `service.Install` stops the old one first.
func portOccupant(addr string) (who string, ours bool) {
	c := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := c.Get("http://" + addr + "/api/health")
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	// Naming the process makes the difference between "stop it" and "stop what?".
	if installed, running, _ := service.Status(); installed && running {
		return "the service that is already installed", true
	}
	return "started by hand, or another trust-proxy", false
}

// pidFileFor finds the pid file of the gateway that is actually running.
//
// It is usually not in the directory being installed into: a gateway started by
// hand keeps its pid file wherever its own --data pointed. The target is checked
// first — on a re-install that is the service's own gateway, the one being
// replaced.
func pidFileFor(dataDirs ...string) (string, bool) {
	for _, dir := range dataDirs {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, "serve.pid")
		if fileExists(p) {
			return p, true
		}
	}
	return "", false
}

// portConflictError explains who is in the way and how to move them.
//
// The pid file is only suggested when there is one: a `serve` running in a
// terminal has no pid file anywhere, and pointing at a path that does not exist
// is worse than saying so — the first version of this message told the user to
// stop a pid file that had never been written.
func portConflictError(addr, who, dataDir string) error {
	msg := fmt.Sprintf("a gateway is already listening on %s (%s).\n"+
		"Installing the service now would give you two: the service would lose the "+
		"port and be restarted forever.\n", addr, who)
	var legacy string
	if home, err := paths.InvokingUserHome(); err == nil {
		legacy = paths.LegacyUserData(home)
	}
	pidPath, hasPid := pidFileFor(dataDir, legacy)
	if hasPid {
		msg += fmt.Sprintf("Stop it:  sudo %s proxy stop --pid %s\n", os.Args[0], pidPath)
	} else {
		msg += "Stop it first — if you have `trust-proxy serve` running in a terminal, that is it (Ctrl-C).\n"
	}
	return fmt.Errorf("%sOr re-run with --takeover to have it stopped for you.", msg)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// gatewayPIDOn works out which process holds the API address.
//
// Three sources, most reliable first, because takeover used to have only the
// middle one and that was not enough on a real machine: a gateway started in a
// terminal never writes a pid file, and an older build does not report its pid
// either. Landing on "stop it yourself, then re-run this" is the exact manual
// step the desktop app exists to remove.
func gatewayPIDOn(addr string, dataDirs ...string) (pid int, from string) {
	// 1. Ask it. Loopback callers get the pid on /api/health.
	c := &http.Client{Timeout: 800 * time.Millisecond}
	if resp, err := c.Get("http://" + addr + "/api/health"); err == nil {
		var body struct {
			PID int `json:"pid"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(&body)
		_ = resp.Body.Close()
		if body.PID > 0 {
			return body.PID, "reported by the gateway itself"
		}
	}
	// 2. A pid file, if one of the directories we know about has it.
	if path, ok := pidFileFor(dataDirs...); ok {
		if n, err := readPidFile(path); err == nil && n > 0 {
			return n, path
		}
	}
	// 3. Ask the OS who is listening. Needs to be able to see a root-owned socket,
	// which is fine: install is root by the time it gets here.
	if n := portOwnerPID(addr); n > 0 {
		return n, "the process listening on " + addr
	}
	return 0, ""
}

// stopGatewayOn stops whatever gateway holds the API address and waits for the
// process to be gone — not merely for the port to free. The listener is the first
// thing a shutting-down gateway releases, and binding in that window leaves two
// processes briefly sharing one bolt lock.
func stopGatewayOn(addr string, dataDirs ...string) error {
	pid, from := gatewayPIDOn(addr, dataDirs...)
	if pid == 0 {
		return fmt.Errorf("a gateway holds %s but would not say which process it is, and "+
			"nothing on this machine could be asked either.\n"+
			"Stop it yourself and re-run this — if it is running in a terminal, that is it (Ctrl-C).", addr)
	}
	// The same guard `proxy stop` uses: a stale pid, or one that has been reused,
	// would otherwise make this signal an unrelated process.
	alive, other := checkPid(pid)
	if other {
		return fmt.Errorf("pid %d (%s) does not look like a trust-proxy process; "+
			"refusing to signal it — stop the gateway on %s yourself", pid, from, addr)
	}
	if alive {
		if p, err := os.FindProcess(pid); err == nil {
			fmt.Printf("stopping the gateway already using %s (pid %d, %s)\n", addr, pid, from)
			if err := p.Signal(syscall.SIGTERM); err != nil {
				return fmt.Errorf("stop pid %d: %w", pid, err)
			}
		}
	}
	// Wait for the *process*, not just the port.
	//
	// The listener is the first thing a shutting-down gateway lets go of; closing
	// the data plane, the detection stores and the log stack all happen after. So
	// "the port is free" arrives seconds before "that gateway is gone", and
	// installing in that window leaves two processes alive — briefly holding the
	// same cache.db, whose bolt lock admits exactly one writer. Measured in the
	// Linux e2e, which counted two gateways after a --takeover that had reported
	// success.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		alive, _ := checkPid(pid)
		if !alive && gatewayOn(addr) == "" {
			// Only now is the pid file meaningless, so only now is it ours to
			// remove. Deleting it up front — before the signal was even known to
			// have worked — turned one failed takeover into a machine where every
			// later takeover had one less way to find the process. A ratchet
			// towards the manual path is the opposite of what this command is for.
			if path, ok := pidFileFor(dataDirs...); ok {
				_ = os.Remove(path)
			}
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("the gateway on %s (pid %d) has not exited after being asked to stop; "+
		"stop it yourself, then re-run this", addr, pid)
}

// ---- adopting the deleted per-user gateway's data --------------------------

// adoptLegacyData copies policy out of the old ~/.trust-proxy exactly once, and
// returns how many files it took.
//
// The per-user gateway is gone, and an upgrade that silently started from an
// empty store would read as "the install wiped my subscriptions". It copies
// rather than moves, and never overwrites: if the machine-wide service turns out
// to be wrong for this box, the old directory is still intact.
//
// No prompt. This runs under an authorization dialog with no terminal attached
// half the time, and a question nobody can answer is just a failed install.
func adoptLegacyData(owner paths.Owner, dst string) int {
	if owner.Home == "" {
		return 0
	}
	src := paths.LegacyUserData(owner.Home)
	if src == dst || !hasGatewayData(src) || hasGatewayData(dst) {
		return 0
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return 0
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		// Only the state that describes policy. cache.db is a bolt file with a
		// single-writer lock, serve.pid/log belong to another process, and
		// jwt-secret/clash-secret are this installation's own — a fresh one mints
		// them, and carrying them over would silently keep old sessions valid.
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		dstPath := filepath.Join(dst, e.Name())
		if _, err := os.Stat(dstPath); err == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			continue
		}
		if os.WriteFile(dstPath, b, 0o600) == nil {
			n++
		}
	}
	return n
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

// ---- config ---------------------------------------------------------------

// serviceDataDir is where the daemon will keep its state: the machine-wide
// directory, unless an operator overrode it.
//
// Its own function because the install has to know this *before* resolving the
// config — see runInstall.
func serviceDataDir() (string, error) {
	data := svcData
	if data == "" {
		data = paths.Data()
	}
	return filepath.Abs(paths.ExpandHome(data))
}

// serviceConfig fills in the defaults the daemon needs: absolute paths (no
// service manager resolves a relative one) and this very binary as the program.
func serviceConfig() (service.Config, error) {
	c := service.Config{APIAddr: svcAPIAddr}
	var err error
	if c.Binary, err = absOrSelf(svcBinary); err != nil {
		return c, err
	}
	if c.DataDir, err = serviceDataDir(); err != nil {
		return c, err
	}
	// Everything that can *refuse* runs before anything that writes.
	//
	// The console check is the one that refuses, and it used to come last — after
	// the config had been seeded. So a rejected install still left a config.json
	// in the machine-wide directory, which then made the directory look like an
	// existing install and silently suppressed the adoption of the user's old
	// policy on the next, successful attempt. Found by the Linux e2e, which is the
	// only place this ordering is visible at all.
	if c.ConsoleDir, err = resolveServiceConsole(); err != nil {
		return c, err
	}
	// Same rule as serve: default to <data>/config.json, seeding it if this is a
	// fresh machine — a service pointing at a config that does not exist would
	// fail at every boot.
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
			"  or point at a built dashboard:   %s install --console /abs/path/to/dashboard/dist\n"+
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
	// re-pointed, and the service manager would keep running the old target.
	return filepath.EvalSymlinks(exe)
}

func init() {
	serviceStatusCmd.Flags().BoolVar(&jsonOut, "json", false, "print the raw JSON response instead of a table")
	// The same commands under both spellings. `install` / `uninstall` are what
	// people type; `service install` is kept working because it is in every old
	// note and script, and breaking it buys nothing.
	serviceCmd.AddCommand(newInstallCmd(true), newUninstallCmd(true), serviceStatusCmd)
}
