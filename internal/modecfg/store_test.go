package modecfg

import (
	"os"
	"path/filepath"
	"testing"
)

// A fresh gateway captures nothing until asked. Anything else would mean
// `install` turns on TUN by itself, which is one of the anti-brick rules.
func TestDefaultIsManual(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "mode.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Get(); got != ModeManual {
		t.Fatalf("fresh store = %q, want %q", got, ModeManual)
	}
}

// The point of the package. Every other policy axis (posture, final, blacklist,
// quarantine, no-proxy, custom rules) is read back from a store on boot; the
// capture mode was read from a CLI flag and stored nowhere, so switching to TUN
// from the console worked until the next restart and then silently stopped
// capturing — gateway healthy, console green, nothing on the network.
func TestSetSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mode.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(ModeTUN); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Get(); got != ModeTUN {
		t.Fatalf("after reopen = %q, want %q — the mode did not survive a restart", got, ModeTUN)
	}
}

func TestSetRejectsUnknownMode(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "mode.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set("turbo"); err == nil {
		t.Fatal("an unknown mode was accepted, so a typo becomes a gateway that captures nothing")
	}
	if got := s.Get(); got != ModeManual {
		t.Fatalf("a rejected Set changed the stored mode to %q", got)
	}
}

// A store that refuses to load is a gateway that refuses to start, so a damaged
// file self-heals to the safe value instead — same rule the other stores follow.
func TestCorruptFileFallsBackToManual(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mode.json")
	if err := os.WriteFile(path, []byte(`{"mode":"nonsense"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("a bad mode file must not stop the gateway: %v", err)
	}
	if got := s.Get(); got != ModeManual {
		t.Fatalf("corrupt store = %q, want %q", got, ModeManual)
	}
}

// The file records which mode is in force, which is enough to tell an attacker
// whether traffic is being intercepted. It is not a secret, but nothing in the
// data directory needs to be world-readable, and the report that prompted this
// package found eight stores at 0644.
func TestFileIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mode.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(ModeSystem); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("mode.json is %#o, want owner-only", perm)
	}
}
