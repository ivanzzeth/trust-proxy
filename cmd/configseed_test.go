package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

const builtIn = `{"builtin":true}`

func setup(t *testing.T) string {
	t.Helper()
	old := defaultConfig
	SetDefaultConfig([]byte(builtIn))
	t.Cleanup(func() { defaultConfig = old })
	// A directory with no checkout in it: the common case for an installed binary.
	t.Chdir(t.TempDir())
	return t.TempDir() // data dir
}

func TestResolveConfigSeedsTheDataDirOnFirstRun(t *testing.T) {
	data := setup(t)
	got, err := resolveConfig("", data)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(data, "config.json")
	if got != want {
		t.Fatalf("config = %s, want %s", got, want)
	}
	if b, _ := os.ReadFile(got); string(b) != builtIn {
		t.Fatalf("seeded content = %q, want the built-in default", b)
	}
}

// The seeded file is the user's from then on: an upgrade that overwrote it would
// silently undo their inbound ports and rules.
func TestResolveConfigNeverOverwritesAnExistingConfig(t *testing.T) {
	data := setup(t)
	path := filepath.Join(data, "config.json")
	if err := os.WriteFile(path, []byte(`{"mine":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveConfig("", data); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != `{"mine":true}` {
		t.Fatalf("existing config was replaced: %q", b)
	}
}

// The old default was configs/config.json, relative to the checkout. Anyone
// running from a repo has been editing *that* file, so it is the seed — being
// quietly ignored in favour of the shipped default is the bad outcome here.
func TestResolveConfigMigratesTheOldRepoRelativeDefault(t *testing.T) {
	data := setup(t)
	if err := os.MkdirAll("configs", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyConfigPath, []byte(`{"edited-in-repo":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := resolveConfig("", data)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(got); string(b) != `{"edited-in-repo":true}` {
		t.Fatalf("seed = %q, want the checkout's config so local edits survive", b)
	}
}

func TestResolveConfigKeepsAnExplicitPath(t *testing.T) {
	data := setup(t)
	got, err := resolveConfig("configs/config.tun.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if got != "configs/config.tun.json" {
		t.Fatalf("explicit -c was rewritten to %s", got)
	}
	// …and nothing was seeded behind its back.
	if _, err := os.Stat(filepath.Join(data, "config.json")); !os.IsNotExist(err) {
		t.Fatal("an explicit -c must not seed the data dir")
	}
}

// A binary with no embedded default and no checkout must say so, not start with
// an empty config.
func TestResolveConfigFailsLoudlyWithNothingToSeedFrom(t *testing.T) {
	data := setup(t)
	SetDefaultConfig(nil)
	if _, err := resolveConfig("", data); err == nil {
		t.Fatal("expected an error when there is no default to seed from")
	}
}
