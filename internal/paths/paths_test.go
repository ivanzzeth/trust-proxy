package paths

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// The one data directory must be machine-wide. A path under somebody's home is
// the shape this refactor deleted: a boot-time daemon cannot rely on a home being
// readable (FileVault, network homes, no login yet), and a root daemon writing
// into a home is what left users with a directory their own desktop app could no
// longer write.
func TestDataIsMachineWideAndOutsideAnyHome(t *testing.T) {
	dir := Data()
	if !filepath.IsAbs(dir) {
		t.Fatalf("the data dir must be absolute: %q", dir)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "/" {
		if strings.HasPrefix(dir+string(filepath.Separator), home+string(filepath.Separator)) {
			t.Fatalf("the data dir is inside a home directory (%s): %s", home, dir)
		}
	}
	// Named explicitly rather than derived, so a change of location is a change a
	// human has to make on purpose — every install on every machine depends on it.
	for _, sep := range []string{"/Library/Application Support/trust-proxy", "/var/lib/trust-proxy", `\ProgramData\trust-proxy`} {
		if strings.HasSuffix(filepath.ToSlash(dir), filepath.ToSlash(sep)) || strings.HasSuffix(dir, sep) {
			return
		}
	}
	t.Fatalf("unexpected data dir %q — if this moved on purpose, update this test", dir)
}

// The credential is the *only* thing left in a home directory, and both sides
// have to agree on where it is: `install` writes it as root into someone else's
// home, the CLI reads it later as that person. A function of the home directory
// alone, with no environment in it, is what makes those two agree.
func TestCredentialsFileIsAPureFunctionOfTheHome(t *testing.T) {
	const home = "/home/someone"
	got := CredentialsFileFor(home)
	if !strings.HasPrefix(got, home+string(filepath.Separator)) {
		t.Fatalf("the credential must live under the home it belongs to: %q", got)
	}
	// Environment must not move it: install runs under sudo, where XDG_CONFIG_HOME
	// is whatever the invoking shell had, and the CLI later runs without it. If
	// either consulted it, the key would land where the other never looks.
	t.Setenv("XDG_CONFIG_HOME", "/tmp/somewhere-else")
	if again := CredentialsFileFor(home); again != got {
		t.Fatalf("the environment moved the credential: %q -> %q", got, again)
	}
	// And it is a credential, not state: never inside the gateway's data dir.
	if strings.HasPrefix(got, Data()) {
		t.Fatalf("the credential is inside the data dir: %q", got)
	}
}

// An elevated command acts for the human who authorized it, not for root: a key
// dropped in /var/root is a key nobody at the keyboard will ever find.
func TestInvokingOwnerPrefersSudoUser(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	t.Setenv("SUDO_USER", me.Username)
	got, err := InvokingOwner()
	if err != nil {
		t.Fatal(err)
	}
	// Unprivileged (the usual test run): SUDO_USER is ignored and we get $HOME.
	// Under root it resolves the named user — both land on this user's home here.
	want, _ := os.UserHomeDir()
	if got.Home != want && got.Home != me.HomeDir {
		t.Fatalf("home = %q, want %q (or %q)", got.Home, want, me.HomeDir)
	}
	t.Setenv("SUDO_USER", "root")
	if got, err := InvokingOwner(); err != nil || got.Home == "" {
		t.Fatalf("SUDO_USER=root must fall back to the process home: %q %v", got.Home, err)
	}
}

func TestLookupOwnerRejectsAStranger(t *testing.T) {
	if _, err := LookupOwner("definitely-not-a-real-account-xyz"); err == nil {
		t.Fatal("claiming for a user who does not exist must fail loudly, not silently drop the key")
	}
}

// The managed binary is the anti-brick rule: a boot-time service must not point
// into an application bundle, which stops existing the moment the app is moved,
// renamed or deleted.
func TestManagedBinaryIsOutsideAnyAppBundle(t *testing.T) {
	if strings.Contains(ManagedBinary(), ".app/") {
		t.Fatalf("managed binary is inside an app bundle: %s", ManagedBinary())
	}
	if !filepath.IsAbs(ManagedBinary()) {
		t.Fatalf("managed binary must be absolute: %s", ManagedBinary())
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	if got := ExpandHome("~/x"); got != filepath.Join(home, "x") {
		t.Fatalf("ExpandHome(~/x) = %q", got)
	}
	// Only a leading ~ is special; a path that merely contains one is left alone.
	for _, p := range []string{"/etc/x", "relative/~x", "~x"} {
		if got := ExpandHome(p); got != p {
			t.Fatalf("ExpandHome(%q) = %q, want it untouched", p, got)
		}
	}
}
