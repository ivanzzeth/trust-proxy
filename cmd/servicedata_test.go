package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Moving a user's gateway data would leave them with nothing to fall back to if
// the service turns out to be wrong for their machine, so the migration copies.
// It must also leave cache.db alone: bolt takes a single-writer lock, and a copy
// in two places is how you end up with two instances that each think they own it.
func TestMigrateServiceDataCopiesPolicyAndNothingElse(t *testing.T) {
	from, to := t.TempDir(), filepath.Join(t.TempDir(), "system")
	write(t, filepath.Join(from, "subscriptions.json"), `{"subs":[]}`)
	write(t, filepath.Join(from, "whitelist.json"), `{"domains":["example.com"]}`)
	write(t, filepath.Join(from, "cache.db"), "bolt")
	write(t, filepath.Join(from, "serve.pid"), "1234")
	write(t, filepath.Join(from, "history.jsonl"), "{}")
	write(t, filepath.Join(from, "ts-node", "state"), "x")

	if err := migrateServiceData(from, to); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"subscriptions.json", "whitelist.json"} {
		if _, err := os.Stat(filepath.Join(to, name)); err != nil {
			t.Fatalf("%s was not copied: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(from, name)); err != nil {
			t.Fatalf("%s was moved, not copied: %v", name, err)
		}
	}
	for _, name := range []string{"cache.db", "serve.pid", "history.jsonl", "ts-node"} {
		if _, err := os.Stat(filepath.Join(to, name)); err == nil {
			t.Fatalf("%s must not be copied", name)
		}
	}
}

// Re-running an install must not overwrite the machine-wide policy with a stale
// copy from someone's home directory.
func TestMigrateServiceDataKeepsWhatIsAlreadyThere(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	write(t, filepath.Join(from, "whitelist.json"), `{"domains":["old.example"]}`)
	write(t, filepath.Join(to, "whitelist.json"), `{"domains":["live.example"]}`)
	if err := migrateServiceData(from, to); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(to, "whitelist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"domains":["live.example"]}` {
		t.Fatalf("existing policy was overwritten: %s", b)
	}
}

func TestHasGatewayData(t *testing.T) {
	dir := t.TempDir()
	if hasGatewayData(dir) {
		t.Fatal("an empty directory must not look like an install")
	}
	// A zero-length file is what a crashed first run leaves behind; treating it
	// as data would offer to migrate nothing.
	write(t, filepath.Join(dir, "whitelist.json"), "")
	if hasGatewayData(dir) {
		t.Fatal("an empty file must not count as data")
	}
	write(t, filepath.Join(dir, "whitelist.json"), `{"domains":[]}`)
	if !hasGatewayData(dir) {
		t.Fatal("a real store must be recognised")
	}
}
