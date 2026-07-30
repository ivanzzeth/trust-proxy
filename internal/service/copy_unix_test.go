//go:build unix

package service

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInstallBinaryForcesLibexecModePastUmask(t *testing.T) {
	redirect(t)
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	src := filepath.Join(t.TempDir(), "src")
	writeBin(t, src, "gateway")
	if _, err := InstallBinary(src); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(ManagedBinary))
	if err != nil {
		t.Fatal(err)
	}
	if perms := info.Mode().Perm(); perms != 0o755 {
		t.Fatalf("managed dir mode = %o, want 0755 (umask must not leave it 0700)", perms)
	}
}
