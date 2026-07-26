package paths

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// The data dir must belong to the human who typed `sudo …`, not to root: a daemon
// installed against an empty /var/root/.trust-proxy would come up with no
// subscriptions and no policy, and nothing would say why.
func TestInvokingUserHomePrefersSudoUser(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	t.Setenv("SUDO_USER", me.Username)
	got, err := InvokingUserHome()
	if err != nil {
		t.Fatal(err)
	}
	// Unprivileged (the usual test run): SUDO_USER is ignored and we get $HOME.
	// Under root it resolves the named user — both land on this user's home here.
	want, _ := os.UserHomeDir()
	if got != want && got != me.HomeDir {
		t.Fatalf("home = %q, want %q (or %q)", got, want, me.HomeDir)
	}
	t.Setenv("SUDO_USER", "root")
	if got, err := InvokingUserHome(); err != nil || got == "" {
		t.Fatalf("SUDO_USER=root must fall back to the process home: %q %v", got, err)
	}
}

// The two directories must never collide: a per-user gateway and a machine-wide
// service on the same box are a supported combination (a laptop that sometimes
// runs its own, sometimes uses the service), and sharing a data dir would mean
// two processes fighting over one bolt cache.
func TestUserAndSystemDataAreDistinct(t *testing.T) {
	u, err := UserData()
	if err != nil {
		t.Skip("no home directory")
	}
	if u == SystemData() {
		t.Fatalf("per-user and machine-wide data dirs are the same: %s", u)
	}
	if !filepath.IsAbs(u) || !filepath.IsAbs(SystemData()) {
		t.Fatalf("both must be absolute: %q %q", u, SystemData())
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
