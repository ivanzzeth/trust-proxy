package cmd

import (
	"os"
	"os/user"
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
	got, err := invokingUserHome()
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
	if got, err := invokingUserHome(); err != nil || got == "" {
		t.Fatalf("SUDO_USER=root must fall back to the process home: %q %v", got, err)
	}
}
