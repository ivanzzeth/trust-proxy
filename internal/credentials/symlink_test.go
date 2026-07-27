//go:build !windows

package credentials

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/paths"
)

// Writing into somebody else's home must not follow a symlink they planted.
//
// `install` runs as root and writes the API key into the target account's home
// directory, and --claim-for names that account — an arbitrary, untrusted one. The
// write was os.WriteFile to path+".tmp" followed by os.Chown, both of which follow
// symlinks, and the directory chain was accepted on a plain os.Stat, which follows
// them too. So a user who pre-created ~/.config/trust-proxy/credentials.json.tmp as
// a link could have root truncate and write a file of their choosing and then hand
// them ownership of it.
//
// Not exotic to reach: it needs one `sudo trust-proxy install --claim-for them` and
// a link placed in advance, and installing on behalf of another account is the
// documented flow.
func TestPutForDoesNotFollowASymlinkedTempFile(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Dir(paths.CredentialsFileFor(home))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tmp := paths.CredentialsFileFor(home) + ".tmp"
	if err := os.Symlink(target, tmp); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	_, err := PutFor(paths.Owner{Home: home, UID: -1, GID: -1}, "127.0.0.1:21585", Entry{Key: "tp_secret", GatewayID: "gw"})

	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("the target file is gone: %v", readErr)
	}
	if string(got) != "original\n" {
		t.Fatalf("the write followed the symlink and overwrote %s (contents now %q); as root "+
			"that is an arbitrary-file write into somebody else's file. PutFor returned %v",
			target, string(got), err)
	}
}

// A symlinked *directory* in the chain is the same trick one level up: the chain is
// accepted with os.Stat, which resolves it, so the credentials land wherever the
// link points and get chowned there.
func TestPutForDoesNotFollowASymlinkedDirectory(t *testing.T) {
	home := t.TempDir()
	elsewhere := t.TempDir()

	if err := os.MkdirAll(filepath.Dir(filepath.Dir(paths.CredentialsFileFor(home))), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Dir(paths.CredentialsFileFor(home))
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	_, err := PutFor(paths.Owner{Home: home, UID: -1, GID: -1}, "127.0.0.1:21585", Entry{Key: "tp_secret", GatewayID: "gw"})

	if _, statErr := os.Stat(filepath.Join(elsewhere, filepath.Base(paths.CredentialsFileFor(home)))); statErr == nil {
		t.Fatalf("the credentials were written through a symlinked directory into %s; "+
			"PutFor returned %v", elsewhere, err)
	}
}

// And the ordinary case still works, or the check is a regression rather than a fix.
func TestPutForStillWritesNormally(t *testing.T) {
	home := t.TempDir()
	if _, err := PutFor(paths.Owner{Home: home, UID: -1, GID: -1}, "127.0.0.1:21585", Entry{Key: "tp_secret", GatewayID: "gw"}); err != nil {
		t.Fatalf("an ordinary write failed: %v", err)
	}
	path := paths.CredentialsFileFor(home)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no credentials file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credentials.json is %#o, want 0600", perm)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Gateways["127.0.0.1:21585"].Key != "tp_secret" {
		t.Fatalf("round-trip lost the key: %+v", f)
	}
}
