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

	"github.com/ivanzzeth/trust-proxy/internal/paths"
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

// legacyOwner points adoptLegacyData at a fake home holding an old per-user
// install, so these can run without touching the real one.
func legacyOwner(t *testing.T) (paths.Owner, string) {
	t.Helper()
	home := t.TempDir()
	return paths.Owner{Username: "someone", Home: home, UID: -1, GID: -1}, paths.LegacyUserData(home)
}

// The per-user gateway is gone, but its policy is the user's: an upgrade that
// started from an empty store would read as "the install wiped my
// subscriptions". It copies rather than moves, so a machine the service turns out
// to be wrong for still has the old directory intact — and it leaves cache.db
// alone, because bolt takes a single-writer lock and a copy in two places is how
// two instances each come to think they own it.
func TestAdoptLegacyDataTakesPolicyAndNothingElse(t *testing.T) {
	owner, from := legacyOwner(t)
	to := filepath.Join(t.TempDir(), "system")
	write(t, filepath.Join(from, "subscriptions.json"), `{"subs":[]}`)
	write(t, filepath.Join(from, "whitelist.json"), `{"domains":["example.com"]}`)
	write(t, filepath.Join(from, "cache.db"), "bolt")
	write(t, filepath.Join(from, "serve.pid"), "1234")
	write(t, filepath.Join(from, "history.jsonl"), "{}")
	write(t, filepath.Join(from, "jwt-secret"), "0123456789abcdef0123456789abcdef")
	write(t, filepath.Join(from, "ts-node", "state"), "x")

	if n := adoptLegacyData(owner, to); n != 2 {
		t.Fatalf("adopted %d files, want the 2 policy ones", n)
	}
	for _, name := range []string{"subscriptions.json", "whitelist.json"} {
		if _, err := os.Stat(filepath.Join(to, name)); err != nil {
			t.Fatalf("%s was not adopted: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(from, name)); err != nil {
			t.Fatalf("%s was moved, not copied: %v", name, err)
		}
	}
	// jwt-secret in particular: carrying it over would silently keep every session
	// minted by the old per-user gateway valid against the new machine-wide one.
	for _, name := range []string{"cache.db", "serve.pid", "history.jsonl", "jwt-secret", "ts-node"} {
		if _, err := os.Stat(filepath.Join(to, name)); err == nil {
			t.Fatalf("%s must not be adopted", name)
		}
	}
}

// Re-running an install must not overwrite live machine-wide policy with a stale
// copy from someone's home directory.
func TestAdoptLegacyDataNeverTouchesALiveInstall(t *testing.T) {
	owner, from := legacyOwner(t)
	to := t.TempDir()
	write(t, filepath.Join(from, "whitelist.json"), `{"domains":["old.example"]}`)
	write(t, filepath.Join(to, "whitelist.json"), `{"domains":["live.example"]}`)
	if n := adoptLegacyData(owner, to); n != 0 {
		t.Fatalf("adopted %d files into a directory that already had data", n)
	}
	b, err := os.ReadFile(filepath.Join(to, "whitelist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"domains":["live.example"]}` {
		t.Fatalf("existing policy was overwritten: %s", b)
	}
}

// Nothing to adopt is the normal case on a fresh machine and must be silent.
func TestAdoptLegacyDataWithNothingToAdopt(t *testing.T) {
	owner, _ := legacyOwner(t)
	if n := adoptLegacyData(owner, t.TempDir()); n != 0 {
		t.Fatalf("adopted %d files from a home with no old install", n)
	}
}

// The account name comes from a system login, which is not required to look
// anything like a username the registry accepts — a Windows account arrives as
// DOMAIN\person. Failing an install over that would be absurd.
func TestAccountNameSurvivesRealLoginNames(t *testing.T) {
	for in, want := range map[string]string{
		"ivan":                  "ivan",
		`CORP\ivan`:             "ivan",
		"ivan.zz@corp":          "ivan.zz@corp",
		"Ivan Zhang":            "Ivan-Zhang",
		"x":                     "admin", // too short for the registry
		"":                      "admin",
		"!!":                    "admin", // nothing usable left after trimming
		strings.Repeat("a", 40): strings.Repeat("a", 32),
	} {
		if got := accountName(in); got != want {
			t.Fatalf("accountName(%q) = %q, want %q", in, got, want)
		}
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

// --takeover has to find the process holding the port. With none of the three
// sources able to name one, it refuses rather than killing something it guessed
// at.
func TestStopGatewayOnRefusesWhenNothingCanNameTheProcess(t *testing.T) {
	dir := t.TempDir()
	err := stopGatewayOn("127.0.0.1:1", dir)
	if err == nil {
		t.Fatal("expected an error when nothing can identify the process")
	}
	if !strings.Contains(err.Error(), "Stop it yourself") {
		t.Fatalf("the error should say what the user can do: %v", err)
	}
}

// A gateway that answers is asked directly, and that answer wins over a pid file.
//
// This is the source that did not exist, and its absence is what sent a real
// takeover back to the command line: the gateway on the port had no pid file
// anywhere (nothing writes one for a `serve` in a terminal, and a previous failed
// takeover had deleted the one that did exist), so the only thing the installer
// could say was "stop it yourself".
func TestGatewayPIDPrefersWhatTheGatewayItselfReports(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			_, _ = io.WriteString(w, `{"status":"ok","pid":4242}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	// A pid file exists and says something else; the live answer is the truth.
	dir := t.TempDir()
	write(t, filepath.Join(dir, "serve.pid"), "1717")
	pid, from := gatewayPIDOn(addr, dir)
	if pid != 4242 {
		t.Fatalf("pid = %d, want the one the gateway reported", pid)
	}
	if !strings.Contains(from, "itself") {
		t.Fatalf("the source should be named as the gateway: %q", from)
	}

	// An older gateway does not report one; the pid file is then the answer.
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	}))
	defer silent.Close()
	pid, from = gatewayPIDOn(strings.TrimPrefix(silent.URL, "http://"), dir)
	if pid != 1717 {
		t.Fatalf("pid = %d, want the one from the pid file", pid)
	}
	if !strings.Contains(from, "serve.pid") {
		t.Fatalf("the source should name the file: %q", from)
	}
}

// --takeover has to find the pid file of the gateway that is actually running,
// which is normally *not* in the directory the service is being installed into:
// you claim a gateway in ~/.trust-proxy, then install the service, which uses
// the machine-wide directory. Looking only there made --takeover fail in exactly
// the case it exists for.
func TestPidFileForPrefersWhereAPidFileActuallyIs(t *testing.T) {
	target, source := t.TempDir(), t.TempDir()
	if got, ok := pidFileFor(target, source); ok {
		t.Fatalf("no pid file anywhere, got %q", got)
	}
	write(t, filepath.Join(source, "serve.pid"), "4242")
	got, ok := pidFileFor(target, source)
	if !ok || got != filepath.Join(source, "serve.pid") {
		t.Fatalf("should have found the source pid file, got %q (%v)", got, ok)
	}
	// When both exist the target wins: that is the service's own, and the one a
	// re-install is replacing.
	write(t, filepath.Join(target, "serve.pid"), "1717")
	if got, _ := pidFileFor(target, source); got != filepath.Join(target, "serve.pid") {
		t.Fatalf("target should win when both exist, got %q", got)
	}
}
