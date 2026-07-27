package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/modecfg"
)

// fakeModeStore records what resolveMode does to the store, which is the part
// that matters: whether the flag is a one-time instruction or a standing one.
type fakeModeStore struct {
	mode   string
	sets   []string
	setErr error
}

func (f *fakeModeStore) Get() string { return f.mode }
func (f *fakeModeStore) Set(m string) (string, error) {
	if f.setErr != nil {
		return f.mode, f.setErr
	}
	f.sets = append(f.sets, m)
	f.mode = m
	return m, nil
}

// No flag: the store decides. This is the path the installed service takes on
// every boot, and it is the fix — the flag used to default to "manual", a
// non-empty value applied unconditionally, so the stored mode did not exist and a
// TUN switch made from the console silently expired at the next restart.
func TestResolveModeWithoutAFlagUsesTheStore(t *testing.T) {
	store := &fakeModeStore{mode: modecfg.ModeTUN}
	got, err := resolveMode("", store)
	if err != nil {
		t.Fatal(err)
	}
	if got != modecfg.ModeTUN {
		t.Fatalf("resolveMode = %q, want the stored %q", got, modecfg.ModeTUN)
	}
	if len(store.sets) != 0 {
		t.Fatalf("a boot with no --mode wrote to the store: %v", store.sets)
	}
}

// An explicit flag applies AND is recorded, so the two can never disagree
// afterwards.
//
// The recording is the whole point. A flag that merely overrode the store on each
// boot would be this same bug with the sign flipped: the console switch would
// apply, appear to work, and then be quietly undone by the next restart — which is
// harder to diagnose than never applying at all, not easier.
func TestResolveModeWithAFlagOverridesAndRecords(t *testing.T) {
	store := &fakeModeStore{mode: modecfg.ModeManual}
	got, err := resolveMode(modecfg.ModeTUN, store)
	if err != nil {
		t.Fatal(err)
	}
	if got != modecfg.ModeTUN {
		t.Fatalf("resolveMode = %q, want %q", got, modecfg.ModeTUN)
	}
	if len(store.sets) != 1 || store.sets[0] != modecfg.ModeTUN {
		t.Fatalf("an explicit --mode was not recorded (sets=%v), so the flag and the store "+
			"disagree and the next restart undoes it", store.sets)
	}
}

func TestResolveModeRejectsGarbage(t *testing.T) {
	store := &fakeModeStore{mode: modecfg.ModeManual}
	if _, err := resolveMode("wide-open", store); err == nil {
		t.Fatal("an invalid --mode was accepted")
	}
	if len(store.sets) != 0 {
		t.Fatalf("a rejected --mode still wrote to the store: %v", store.sets)
	}
}

// The scenario the whole change exists for: upgrade a machine that runs TUN.
//
// `install.sh` and the desktop Update button both run a bare `trust-proxy
// install`. That has to mean "leave this machine's setting alone" — and while the
// mode lived in the service definition's arguments it could not, because rewriting
// that definition dropped the argument and the gateway came back in manual, still
// healthy, no longer capturing anything.
func TestBareInstallPreservesTUN(t *testing.T) {
	dir := t.TempDir()

	if got, err := seedMode(dir, modecfg.ModeTUN); err != nil || got != modecfg.ModeTUN {
		t.Fatalf("seedMode(tun) = %q, %v", got, err)
	}
	// The upgrade: same command, no --mode.
	got, err := seedMode(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != modecfg.ModeTUN {
		t.Fatalf("after a bare re-install the mode is %q, want %q — upgrading silently "+
			"turned capture off", got, modecfg.ModeTUN)
	}
}

// A first install with no --mode captures nothing until asked. Anything else would
// break the anti-brick rule that installing never enables TUN by itself.
func TestFirstInstallDefaultsToManual(t *testing.T) {
	got, err := seedMode(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if got != modecfg.ModeManual {
		t.Fatalf("a fresh install starts in %q, want %q", got, modecfg.ModeManual)
	}
}

// seedMode runs before the service is registered, so it must not leave a mode
// behind that the install then failed to deliver on. Nothing to assert about
// ordering from here, but the file it writes must at least be owner-only: the data
// directory is machine-wide and readable by every local account otherwise.
func TestSeedModeWritesAnOwnerOnlyFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := seedMode(dir, modecfg.ModeSystem); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "mode.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("mode.json is %#o, want owner-only", perm)
	}
}
