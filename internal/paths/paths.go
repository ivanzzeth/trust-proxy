// Package paths answers "where does this OS want our files" in one place.
//
// The gateway runs in two shapes, and they want different directories:
//
//   - **per-user** (`trust-proxy serve` typed by a human) — everything under the
//     invoking user's home, so no elevation is needed to change policy.
//   - **machine-wide** (installed as a service: launchd / systemd / SCM) — the
//     daemon runs as root/SYSTEM before anyone logs in, so its data cannot live
//     in a home directory. On macOS a home directory may not even be readable at
//     boot (FileVault, network homes), and on Windows the SYSTEM profile is not
//     the user's.
//
// Keeping these in one package rather than scattered `filepath.Join(home, ...)`
// calls is what makes the Windows and Linux ports mechanical rather than a hunt
// for hardcoded macOS paths.
package paths

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

// dirName is the same on every platform, capitalised where the platform expects
// it (Windows shows these directories to people; Unix hides them).
const (
	unixDirName = ".trust-proxy"
	winDirName  = "trust-proxy"
)

// UserData is the per-user data directory: subscriptions, policy, cache.db, logs.
//
// macOS/Linux keep ~/.trust-proxy — it predates this package and moving it would
// orphan every existing install for no benefit. Windows uses %LOCALAPPDATA%,
// which is what a per-user, machine-local, not-roamed store is for (roaming a
// bolt cache between machines would corrupt it).
func UserData() (string, error) {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, winDirName), nil
		}
	}
	home, err := InvokingUserHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, unixDirName), nil
}

// SystemData is the machine-wide data directory used when we are installed as a
// service. Root/SYSTEM owns it; a non-privileged user is not meant to write here,
// which is the point: the policy a boot-time daemon enforces must not be editable
// by whoever happens to be logged in.
func SystemData() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, winDirName)
	case "darwin":
		// Apple's documented location for a daemon's support files. Not
		// /var/lib (not a thing on macOS) and not /usr/local (may not exist,
		// and is user-writable on Intel Homebrew machines — a user-writable
		// policy store defeats the daemon).
		return "/Library/Application Support/trust-proxy"
	default:
		return "/var/lib/trust-proxy" // FHS: state a daemon keeps across reboots
	}
}

// ManagedBinary is where `service install` copies the binary so the service
// entry can point at a stable path.
//
// It must not point inside an application bundle: the moment the user moves,
// renames, updates or deletes the app, a boot-time service pointing into it
// either fails or — worse, with TUN — leaves a machine whose network was set up
// by something that no longer exists.
func ManagedBinary() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(SystemData(), "bin", "trust-proxy.exe")
	default:
		// libexec is the convention for a program run by other programs rather
		// than typed by a human.
		return "/usr/local/libexec/trust-proxy"
	}
}

// ServiceLog is the default log path for the installed service.
func ServiceLog(dataDir string) string { return filepath.Join(dataDir, "serve.log") }

// InvokingUserHome is the home directory of the human who typed the command, not
// of root.
//
// `service install` runs under sudo. macOS sudo happens to keep HOME, so
// os.UserHomeDir() usually returns the right thing — but that is a sudoers detail
// (`sudo -H`, or a different env_reset policy, gives /var/root). Getting it wrong
// is silent and nasty: the daemon would install against an empty
// /var/root/.trust-proxy while every subscription and policy the user has sits in
// their own home.
func InvokingUserHome() (string, error) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
			if u, err := user.Lookup(name); err == nil && u.HomeDir != "" {
				return u.HomeDir, nil
			}
		}
	}
	return os.UserHomeDir()
}

// ExpandHome resolves a leading ~ so flags can carry one.
func ExpandHome(p string) string {
	if p == "~" || len(p) > 1 && (p[:2] == "~/" || runtime.GOOS == "windows" && p[:2] == `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}
