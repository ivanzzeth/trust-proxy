//go:build unix

package service

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The service definition has to survive `install`'s umask 0077, or the readers
// that key off it all degrade at once — and they degrade quietly: Program()
// returns "", BinaryMissing("") is false, and the stale-gateway warning in the
// Makefile can never fire. The real symptom was an app attached to a daemon four
// commits older than itself, with nothing on screen to say so.
func TestServiceDefinitionStaysReadablePastUmask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "io.trust-proxy.gateway.plist")
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	if err := writeServiceDefinition(path, "<plist/>"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Fatalf("definition mode = %o, want 0644: at %o nothing unprivileged can read "+
			"back which binary the service runs, and every staleness check goes quiet", perm, perm)
	}
}

// redirectDefinition points File() at a temp path on whichever OS is running.
func redirectDefinition(t *testing.T, path string) {
	t.Helper()
	oldPlist, oldUnit := PlistPath, UnitPath
	PlistPath, UnitPath = path, path
	t.Cleanup(func() { PlistPath, UnitPath = oldPlist, oldUnit })
}

// An unreadable definition must be its own answer, not an empty program: the two
// are indistinguishable to every caller otherwise, and the wrong one of them is
// treated as "fine, nothing to check".
func TestDefinitionUnreadableIsDistinctFromNotInstalled(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any mode, so the unreadable case cannot be staged")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "definition")
	redirectDefinition(t, path)

	if DefinitionUnreadable() {
		t.Fatal("no definition on disk: want false (not installed), got unreadable")
	}
	if err := os.WriteFile(path, []byte("ExecStart=/usr/local/libexec/trust-proxy serve\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if DefinitionUnreadable() {
		t.Fatal("0644 definition reported unreadable")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// 0600 owned by *us* is still readable by us; drop our own read bit to stage
	// the state a non-root caller sees against a root-owned 0600 file.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	if !DefinitionUnreadable() {
		t.Fatal("unreadable definition reported as fine; Program() would return \"\" and " +
			"every check downstream would read that as nothing to warn about")
	}
}
