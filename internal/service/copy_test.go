package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// redirect points ManagedBinary at a temp dir so these can run unprivileged.
func redirect(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := ManagedBinary
	ManagedBinary = filepath.Join(dir, "libexec", "trust-proxy")
	t.Cleanup(func() { ManagedBinary = old })
	return dir
}

func writeBin(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// The brick this exists to prevent: launchd pointing inside an .app that the user
// later moves to the Trash. The daemon must get its own copy, outside the bundle.
func TestInstallBinaryCopiesOutOfTheBundleAndSurvivesItsRemoval(t *testing.T) {
	dir := redirect(t)
	bundle := filepath.Join(dir, "Trust Proxy.app", "Contents", "MacOS", "trust-proxy")
	writeBin(t, bundle, "#!/bin/sh\necho gateway\n")

	got, err := InstallBinary(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got != ManagedBinary {
		t.Fatalf("plist would point at %s, want the managed copy %s", got, ManagedBinary)
	}
	if strings.Contains(got, ".app/") {
		t.Fatal("the daemon must not be pointed inside an .app bundle")
	}
	// Trash the app: the copy must still be there and still executable.
	if err := os.RemoveAll(filepath.Join(dir, "Trust Proxy.app")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(ManagedBinary)
	if err != nil {
		t.Fatalf("the managed copy did not survive removing the app: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("the copy is not executable (%v)", info.Mode())
	}
	if data, _ := os.ReadFile(ManagedBinary); !strings.Contains(string(data), "echo gateway") {
		t.Fatal("the copy does not have the source's contents")
	}
}

// Re-installing the same build must not churn the file a running daemon is
// executing.
func TestInstallBinaryIsIdempotent(t *testing.T) {
	dir := redirect(t)
	src := filepath.Join(dir, "trust-proxy")
	writeBin(t, src, "same bytes")

	if _, err := InstallBinary(src); err != nil {
		t.Fatal(err)
	}
	first, err := os.Stat(ManagedBinary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallBinary(src); err != nil {
		t.Fatal(err)
	}
	second, err := os.Stat(ManagedBinary)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(first, second) || !first.ModTime().Equal(second.ModTime()) {
		t.Fatal("an unchanged binary was replaced anyway")
	}

	// A new build does get copied.
	writeBin(t, src, "new bytes")
	if _, err := InstallBinary(src); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(ManagedBinary); string(data) != "new bytes" {
		t.Fatalf("the copy was not updated: %q", data)
	}
}

// Uninstall is an escape hatch, and an escape hatch that deletes the user's
// Homebrew binary is a new problem. It removes only the copy we made.
func TestRemoveManagedBinaryOnlyTouchesOurCopy(t *testing.T) {
	dir := redirect(t)
	foreign := filepath.Join(dir, "brew", "bin", "trust-proxy")
	writeBin(t, foreign, "not ours")
	writeBin(t, ManagedBinary, "ours")

	if err := RemoveManagedBinary(foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("a binary we did not install was deleted")
	}
	if _, err := os.Stat(ManagedBinary); err != nil {
		t.Fatal("our copy was deleted while removing someone else's path")
	}

	if err := RemoveManagedBinary(ManagedBinary); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ManagedBinary); !os.IsNotExist(err) {
		t.Fatal("our copy should be gone")
	}
	// Already gone: still fine (uninstall must converge from any state).
	if err := RemoveManagedBinary(ManagedBinary); err != nil {
		t.Fatalf("second removal failed: %v", err)
	}
}

// Status has to be able to say "launchd is pointing at nothing", because that is
// the failure that otherwise only shows up as a boot-time retry loop in a log.
func TestProgramFromPlistAndMissingDetection(t *testing.T) {
	dir := redirect(t)
	bin := filepath.Join(dir, "some & path", "trust-proxy")
	writeBin(t, bin, "x")
	c := Config{
		Binary: bin, ConfigPath: "/etc/tp/config.json", DataDir: "/var/lib/tp",
		APIAddr: "127.0.0.1:21585", LogPath: "/var/log/tp.log",
	}
	plist, err := c.Plist()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "plist.plist")
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	old := PlistPath
	PlistPath = path
	t.Cleanup(func() { PlistPath = old })

	got := ProgramFromPlist()
	if got != bin {
		t.Fatalf("program = %q, want %q (XML escaping must round-trip)", got, bin)
	}
	if BinaryMissing(got) {
		t.Fatal("the binary exists")
	}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	if !BinaryMissing(got) {
		t.Fatal("a deleted program must be reported as missing")
	}
	if BinaryMissing("") {
		t.Fatal("an unknown program is not a missing one")
	}
}
