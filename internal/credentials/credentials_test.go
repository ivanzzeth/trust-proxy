package credentials

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/paths"
)

func TestPutGetRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if _, ok := Get(path, "127.0.0.1:21585"); ok {
		t.Fatal("a missing file must read as 'no credential', not as an error state")
	}
	if err := Put(path, "127.0.0.1:21585", Entry{GatewayID: "g1", Key: "tp_abc", Username: "ivan"}); err != nil {
		t.Fatal(err)
	}
	got, ok := Get(path, "127.0.0.1:21585")
	if !ok || got.Key != "tp_abc" || got.GatewayID != "g1" {
		t.Fatalf("round trip lost the entry: %+v (%v)", got, ok)
	}
	// The address is the key, so a second gateway does not overwrite the first.
	if err := Put(path, "10.0.0.9:21585", Entry{GatewayID: "g2", Key: "tp_def"}); err != nil {
		t.Fatal(err)
	}
	if first, _ := Get(path, "127.0.0.1:21585"); first.Key != "tp_abc" {
		t.Fatalf("a second gateway clobbered the first: %+v", first)
	}
	// Case and stray whitespace in --api-addr must not mint a second entry that
	// shadows the real one.
	if got, ok := Get(path, " 127.0.0.1:21585 "); !ok || got.Key != "tp_abc" {
		t.Fatalf("address normalisation failed: %+v (%v)", got, ok)
	}
}

// The whole reason this file was allowed back: a key that outlives the registry
// it belongs to must be *recognisable* as stale, not just wrong. The id travels
// with the key so the caller can tell those apart.
func TestTheGatewayIdTravelsWithTheKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := Put(path, "127.0.0.1:21585", Entry{GatewayID: "before-reinstall", Key: "tp_old"}); err != nil {
		t.Fatal(err)
	}
	got, _ := Get(path, "127.0.0.1:21585")
	if got.GatewayID == "" {
		t.Fatal("without the gateway id a stale key is indistinguishable from a wrong one")
	}
	if got.GatewayID == "after-reinstall" {
		t.Fatal("the stored id must be the one it was minted against")
	}
}

// A corrupt file must not be a dead end: logging in again is the recovery, and it
// cannot depend on the thing that is broken.
func TestACorruptFileStillAcceptsAFreshLogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := Get(path, "127.0.0.1:21585"); ok {
		t.Fatal("a corrupt file must read as 'no credential'")
	}
	if err := Put(path, "127.0.0.1:21585", Entry{GatewayID: "g", Key: "tp_new"}); err != nil {
		t.Fatalf("a corrupt file blocked a fresh login: %v", err)
	}
	if got, ok := Get(path, "127.0.0.1:21585"); !ok || got.Key != "tp_new" {
		t.Fatalf("the fresh login did not stick: %+v", got)
	}
}

func TestForget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	_ = Put(path, "a:1", Entry{GatewayID: "g", Key: "tp_a"})
	_ = Put(path, "b:2", Entry{GatewayID: "g", Key: "tp_b"})
	if err := Forget(path, "a:1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := Get(path, "a:1"); ok {
		t.Fatal("forget left the entry behind")
	}
	if _, ok := Get(path, "b:2"); !ok {
		t.Fatal("forget took the wrong entry")
	}
}

// `install` runs as root and drops the key in somebody else's home. A 0600 file
// owned by root there is the same as no key at all, so ownership is the claim —
// and the file must never be group- or world-readable, because it is an admin
// credential for the machine's gateway.
func TestPutForLandsInTheOwnersHomeAndIsPrivate(t *testing.T) {
	home := t.TempDir()
	owner := paths.Owner{Username: "someone", Home: home, UID: -1, GID: -1} // -1: no chown in a test
	path, err := PutFor(owner, "127.0.0.1:21585", Entry{GatewayID: "g", Key: "tp_installed", Username: "someone"})
	if err != nil {
		t.Fatal(err)
	}
	if want := paths.CredentialsFileFor(home); path != want {
		t.Fatalf("wrote to %q, want %q — install and the CLI must agree on one path", path, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("the credential is readable by others: %v", mode)
	}
	if got, ok := Get(path, "127.0.0.1:21585"); !ok || got.Key != "tp_installed" {
		t.Fatalf("the CLI cannot read what install wrote: %+v (%v)", got, ok)
	}
	// The directory it had to create is private too.
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := dir.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("the credential directory is open to others: %v", mode)
	}
}

// Only what we create gets chowned. Re-homing somebody's whole ~/.config because
// we happened to write one file inside it is not ours to do.
func TestPutForLeavesAnExistingConfigDirAlone(t *testing.T) {
	home := t.TempDir()
	existing := filepath.Dir(filepath.Dir(paths.CredentialsFileFor(home))) // ~/.config
	if err := os.MkdirAll(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(existing)
	if err != nil {
		t.Fatal(err)
	}
	owner := paths.Owner{Username: "someone", Home: home, UID: -1, GID: -1}
	if _, err := PutFor(owner, "127.0.0.1:21585", Entry{GatewayID: "g", Key: "tp_x"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(existing)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() {
		t.Fatalf("an existing config dir was modified: %v -> %v", before.Mode(), after.Mode())
	}
}
