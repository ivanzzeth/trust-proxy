// Package paths answers "where does this OS want our files" in one place.
//
// There is exactly **one** gateway on a machine and it is machine-wide: it runs
// as root/SYSTEM under the platform's service manager, starts at boot before
// anyone logs in, and keeps its state in a directory no logged-in user can edit.
// That is not a deployment option, it is the only shape — see `trust-proxy
// install`.
//
// There used to be a second shape, a per-user gateway under ~/.trust-proxy, and
// it is gone. It could not do TUN (that needs root), it died with the window that
// started it, and the moment anyone ran the gateway with sudo it left a
// root-owned directory in a home the unprivileged app could no longer write —
// which is what "it works on macOS and explodes on Linux" actually was. The only
// thing left in a home directory is a *credential* (see CredentialsFileFor):
// a secret the owner uses to talk to the machine's gateway, never state the
// gateway itself reads.
package paths

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
)

// dirName is the same on every platform, capitalised where the platform expects
// it (Windows shows these directories to people; Unix hides them).
const (
	unixDirName = ".trust-proxy"
	winDirName  = "trust-proxy"
)

// Data is *the* data directory: subscriptions, policy, cache.db, logs, accounts.
//
// Machine-wide, root/SYSTEM-owned. A non-privileged user is not meant to write
// here, and that is the point: the policy a boot-time daemon enforces must not be
// editable by whoever happens to be logged in.
func Data() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, winDirName)
	case "darwin":
		// Apple's documented location for a daemon's support files. Not /var/lib
		// (not a thing on macOS) and not /usr/local (may not exist, and is
		// user-writable on Intel Homebrew machines — a user-writable policy store
		// defeats the daemon).
		return "/Library/Application Support/trust-proxy"
	default:
		return "/var/lib/trust-proxy" // FHS: state a daemon keeps across reboots
	}
}

// LegacyUserData is the directory the deleted per-user gateway used.
//
// It exists for exactly one purpose: `install` adopts it once, so upgrading does
// not look like "the install wiped my subscriptions". Nothing else may read it,
// and nothing ever writes it again.
func LegacyUserData(home string) string {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, winDirName)
		}
	}
	return filepath.Join(home, unixDirName)
}

// CredentialsFileFor is where the CLI keeps its API key for a gateway, in the
// home directory of the person who owns it.
//
// A pure function of the home directory, deliberately: `install` runs as root and
// has to write this file into *someone else's* home and chown it to them, while
// the CLI later reads it as that person. If one side consulted XDG_CONFIG_HOME
// and the other did not, install would drop the key somewhere the CLI never
// looks — so neither does.
func CredentialsFileFor(home string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Local", winDirName, "credentials.json")
	}
	return filepath.Join(home, ".config", "trust-proxy", "credentials.json")
}

// CredentialsFile is CredentialsFileFor this process's user.
func CredentialsFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return CredentialsFileFor(home), nil
}

// ManagedBinary is where `install` copies the binary so the service entry can
// point at a stable path.
//
// It must not point inside an application bundle: the moment the user moves,
// renames, updates or deletes the app, a boot-time service pointing into it
// either fails or — worse, with TUN — leaves a machine whose network was set up
// by something that no longer exists.
func ManagedBinary() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(Data(), "bin", "trust-proxy.exe")
	default:
		// libexec is the convention for a program run by other programs rather
		// than typed by a human.
		return "/usr/local/libexec/trust-proxy"
	}
}

// ServiceLog is the default log path for the installed service.
func ServiceLog(dataDir string) string { return filepath.Join(dataDir, "serve.log") }

// Owner is the human an elevated command is acting on behalf of: the one who
// typed `sudo`, or who answered the desktop app's authorization prompt.
//
// `install` needs this to put the API key somewhere they can read it. Getting it
// wrong is silent and useless — a credential dropped in /var/root that the person
// at the keyboard will never find.
type Owner struct {
	Username string
	Home     string
	UID, GID int // -1 where the concept does not apply (Windows)
}

// InvokingOwner resolves who is really behind this command.
//
// Under sudo that is SUDO_USER, not root. macOS sudo happens to keep HOME so
// os.UserHomeDir() is often right anyway, but that is a sudoers detail (`sudo -H`
// or a different env_reset policy gives /var/root) and it is not something to
// depend on when the result decides where a secret lands.
func InvokingOwner() (Owner, error) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
			if u, err := user.Lookup(name); err == nil && u.HomeDir != "" {
				return ownerFrom(u), nil
			}
		}
	}
	u, err := user.Current()
	if err != nil {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return Owner{}, err
		}
		return Owner{Home: home, UID: -1, GID: -1}, nil
	}
	return ownerFrom(u), nil
}

// LookupOwner resolves a named account, for `install --claim-for <user>` where
// the desktop shell says who authorized it.
func LookupOwner(name string) (Owner, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return Owner{}, fmt.Errorf("no such user %q on this machine: %w", name, err)
	}
	if u.HomeDir == "" {
		return Owner{}, fmt.Errorf("user %q has no home directory to put a credential in", name)
	}
	return ownerFrom(u), nil
}

func ownerFrom(u *user.User) Owner {
	o := Owner{Username: u.Username, Home: u.HomeDir, UID: -1, GID: -1}
	if runtime.GOOS == "windows" {
		return o
	}
	if n, err := strconv.Atoi(u.Uid); err == nil {
		o.UID = n
	}
	if n, err := strconv.Atoi(u.Gid); err == nil {
		o.GID = n
	}
	return o
}

// InvokingUserHome is the home directory of the human who typed the command.
func InvokingUserHome() (string, error) {
	o, err := InvokingOwner()
	if err != nil {
		return "", err
	}
	return o.Home, nil
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
