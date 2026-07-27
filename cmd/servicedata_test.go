package cmd

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// Installing a service while another gateway holds the API port produces a
// daemon that can never bind and is retried at every boot — with the machine
// looking fine, because the other gateway answers. So the install looks first.
func TestGatewayOnDetectsAnAnswerOnThePort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			_, _ = io.WriteString(w, `{"status":"ok"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if gatewayOn(addr) == "" {
		t.Fatal("a gateway answering /api/health must be detected")
	}
	// A free port must not read as occupied, or every install on a clean machine
	// would refuse.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	free := l.Addr().String()
	_ = l.Close()
	if who := gatewayOn(free); who != "" {
		t.Fatalf("nothing is listening on %s, got %q", free, who)
	}
}

// --takeover stops the gateway in the way; with no pid file it must say so
// rather than killing something it guessed at.
func TestStopGatewayOnRefusesWithoutAPidFile(t *testing.T) {
	dir := t.TempDir()
	err := stopGatewayOn("127.0.0.1:1", dir)
	if err == nil {
		t.Fatal("expected an error when there is no pid file")
	}
	if !strings.Contains(err.Error(), "pid file") {
		t.Fatalf("the error should name the missing pid file: %v", err)
	}
}
