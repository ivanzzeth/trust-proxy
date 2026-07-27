//go:build desktop_e2e

// What is actually inside the shipped desktop bundle, and does it still line up
// with the gateway.
//
// This exists because of a real failure: a bundle built before the ports were
// renumbered kept probing the old API address, never found the gateway that was
// running, and sat on "starting the gateway" forever — while every other suite in
// this repo was green, because none of them ever looked at the .app. Two kinds of
// drift caused it, and both are checked here:
//
//   - the shell's default API address vs the gateway's default --api-addr
//   - the bundled sidecar being an old or non-embed_ui build, which serves
//     "dashboard not built" instead of a console
//
// Run with: make e2e-desktop   (skips when there is no bundle to look at)
package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

type bundle struct {
	path    string
	shell   string
	sidecar string
}

func TestDesktopBundleMatchesTheGateway(t *testing.T) {
	b := requireBundle(t)

	cfg := b.printConfig(t)
	// The gateway's own default, read from its flags rather than hardcoded here —
	// a constant in the test would drift with exactly the thing it is checking.
	want := gatewayDefaultAPI(t, b.sidecar)
	if cfg.API != want {
		t.Fatalf("the shell would probe %s but the gateway listens on %s by default.\n"+
			"That is the stale-bundle failure: the shell waits on an address nobody answers "+
			"and the window never leaves the splash. Rebuild with `make desktop`.", cfg.API, want)
	}
	if cfg.Sidecar == "" {
		t.Fatal("the shell cannot find its own sidecar")
	}
	if _, err := os.Stat(cfg.Sidecar); err != nil {
		t.Fatalf("the sidecar the shell would run does not exist: %v", err)
	}
	// Is the bundle current? Only meaningful for the one this repo builds — an
	// app someone installed weeks ago is legitimately behind the tree, and the
	// address check above already covers the drift that actually breaks it.
	//
	// (The shell's own version is Tauri's app version from tauri.conf.json, a
	// different numbering entirely, so comparing the two halves proves nothing.)
	if strings.HasPrefix(b.path, repoRoot(t)) {
		if repo, side := gitDescribe(t), version(t, b.sidecar); repo != "" && repo != side {
			t.Fatalf("this bundle's gateway is %s but the tree is at %s — `make desktop` was not "+
				"re-run after the last change, which is how a stale .app gets shipped", side, repo)
		}
	} else {
		t.Logf("installed bundle, gateway %s (tree: %s)", version(t, b.sidecar), gitDescribe(t))
	}
}

// The sidecar inside a bundle must carry the console: there is no dashboard/dist
// next to a .app, so a plain `make build` sidecar answers "dashboard not built"
// on every page — an install that reports success and then shows nothing.
func TestBundledSidecarServesAConsole(t *testing.T) {
	b := requireBundle(t)

	data := t.TempDir()
	cfgPath := writeTestConfig(t, data)
	api := "127.0.0.1:" + fmt.Sprint(freeTCPPort(t))

	cmd := exec.Command(b.sidecar, "serve",
		"-c", cfgPath, "--data", data, "--api-addr", api,
		"--clash-addr", "127.0.0.1:"+fmt.Sprint(freeTCPPort(t)),
		"--no-threat-feed")
	// A gateway of our own, on its own ports and its own data dir: this must not
	// disturb whatever the developer has running.
	out, err := os.Create(filepath.Join(data, "serve.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the bundled sidecar: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			if body, err := os.ReadFile(filepath.Join(data, "serve.log")); err == nil {
				t.Logf("--- sidecar log ---\n%s", tail(string(body), 30))
			}
		}
	})
	waitHTTP(t, "http://"+api+"/api/health", 30*time.Second)

	body := get(t, "http://"+api+"/")
	if strings.Contains(body, "dashboard not built") {
		t.Fatalf("the bundled sidecar has no console in it — build it with `make build-embed` "+
			"(that is what `make desktop` does) — got: %s", strings.TrimSpace(body))
	}
	if !strings.Contains(strings.ToLower(body), "<!doctype html") {
		t.Fatalf("/ did not serve the console: %s", tail(body, 5))
	}
	// The console is only useful if its assets load too; a half-embedded build
	// serves index.html and 404s the bundle it references.
	asset := regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`).FindStringSubmatch(body)
	if asset == nil {
		t.Fatalf("index.html references no /assets/ bundle:\n%s", tail(body, 10))
	}
	if code := status(t, "http://"+api+asset[1]); code != http.StatusOK {
		t.Fatalf("asset %s → %d (the console would load blank)", asset[1], code)
	}
}

// The GUI half: with a gateway already running the shell must attach to it, not
// start a second one (two gateways on one data dir fight over cache.db's single
// writer lock, and the second one hangs rather than failing).
//
// Opt-in: launching it puts a window on the screen of whoever runs the suite.
func TestDesktopShellAttachesToARunningGateway(t *testing.T) {
	if os.Getenv("TP_DESKTOP_GUI") == "" {
		t.Skip("opens a window; set TP_DESKTOP_GUI=1 to run")
	}
	b := requireBundle(t)

	data := t.TempDir()
	cfgPath := writeTestConfig(t, data)
	api := "127.0.0.1:" + fmt.Sprint(freeTCPPort(t))
	gw := exec.Command(b.sidecar, "serve", "-c", cfgPath, "--data", data, "--api-addr", api,
		"--clash-addr", "127.0.0.1:"+fmt.Sprint(freeTCPPort(t)), "--no-threat-feed")
	if err := gw.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Process.Kill(); _, _ = gw.Process.Wait() })
	waitHTTP(t, "http://"+api+"/api/health", 30*time.Second)

	shell := exec.Command(b.shell)
	shell.Env = append(os.Environ(), "TP_API_ADDR="+api, "TP_DATA="+data)
	if err := shell.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shell.Process.Kill(); _, _ = shell.Process.Wait() }()
	time.Sleep(6 * time.Second) // let it probe, decide, and load the console

	if kids := children(t, shell.Process.Pid); len(kids) > 0 {
		t.Fatalf("the shell started its own gateway (%v) instead of attaching to the one on %s", kids, api)
	}
	if code := status(t, "http://"+api+"/api/health"); code != http.StatusOK {
		t.Fatalf("the gateway we started is no longer answering (%d) — the shell interfered with it", code)
	}
}

// ---- helpers --------------------------------------------------------------

func requireBundle(t *testing.T) bundle {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skipf("the .app bundle is macOS-only (this is %s)", runtime.GOOS)
	}
	candidates := []string{
		os.Getenv("TP_APP_BUNDLE"),
		filepath.Join(repoRoot(t), "desktop/src-tauri/target/release/bundle/macos/Trust Proxy.app"),
		"/Applications/Trust Proxy.app",
	}
	for _, path := range candidates {
		if path == "" {
			continue
		}
		b := bundle{
			path:    path,
			shell:   filepath.Join(path, "Contents/MacOS/trust-proxy-desktop"),
			sidecar: filepath.Join(path, "Contents/MacOS/trust-proxy"),
		}
		if fileIsExecutable(b.shell) && fileIsExecutable(b.sidecar) {
			t.Logf("bundle: %s", path)
			return b
		}
	}
	t.Skip("no desktop bundle found (build one with `make desktop`, or set TP_APP_BUNDLE)")
	return bundle{}
}

type shellConfig struct {
	API     string `json:"api"`
	DataDir string `json:"data_dir"`
	Sidecar string `json:"sidecar"`
}

// printConfig asks the shell what it would do, which is the only way to read its
// compiled-in defaults without opening a window.
//
// Under a timeout, because a bundle older than the flag does not fail on it — it
// ignores the unknown argument and starts the GUI, which never exits. Measured:
// the first run of this suite hung for minutes with a window on screen. A stale
// bundle is exactly what this test is for, so that has to be a failure with a
// useful message, not a hang.
func (b bundle) printConfig(t *testing.T) shellConfig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.shell, "--print-config")
	// The compiled-in defaults are what ship, so the developer's own TP_* overrides
	// must not stand in for them here.
	cmd.Env = envWithout(os.Environ(), "TP_API_ADDR", "TP_BINARY", "TP_DATA")
	out, err := cmd.Output()
	if ctx.Err() != nil {
		t.Fatalf("`--print-config` never returned — this bundle predates the flag and opened " +
			"a window instead, which is the stale-bundle failure itself. Rebuild: `make desktop`")
	}
	if err != nil {
		t.Fatalf("`--print-config` failed (%v) — a bundle older than this flag is itself "+
			"the stale-bundle problem; rebuild with `make desktop`", err)
	}
	var cfg shellConfig
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("--print-config output is not JSON: %s", out)
	}
	return cfg
}

// gitDescribe is what a build made right now would stamp into the gateway, i.e.
// the same expression the Makefile uses for VERSION.
func gitDescribe(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("git", "describe", "--tags", "--always", "--dirty")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// gatewayDefaultAPI reads the gateway's own default out of its flag help, so this
// test cannot drift away from the value it is checking.
func gatewayDefaultAPI(t *testing.T, gateway string) string {
	t.Helper()
	out, err := exec.Command(gateway, "serve", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("read the gateway's flags: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`--api-addr string\s+.*?\(default "([^"]+)"\)`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("could not find the --api-addr default in `serve --help`")
	}
	return string(m[1])
}

func version(t *testing.T, bin string) string {
	t.Helper()
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	return fields[len(fields)-1]
}

// writeTestConfig produces a config on free ports, so running this suite never
// collides with a gateway the developer already has up.
func writeTestConfig(t *testing.T, dir string) string {
	t.Helper()
	cfg := map[string]any{
		"log": map[string]any{"level": "info"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "mixed-in",
			"listen": "127.0.0.1", "listen_port": freeTCPPort(t),
		}},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "blocked"},
		},
		"route": map[string]any{
			"rules": []any{map[string]any{"action": "sniff"}},
			"final": "direct",
		},
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": "127.0.0.1:" + fmt.Sprint(freeTCPPort(t)),
			},
		},
	}
	body, _ := json.MarshalIndent(cfg, "", "  ")
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func children(t *testing.T, pid int) []string {
	t.Helper()
	out, _ := exec.Command("pgrep", "-P", fmt.Sprint(pid)).Output()
	var kids []string
	for _, line := range strings.Fields(string(out)) {
		args, _ := exec.Command("ps", "-o", "args=", "-p", line).Output()
		kids = append(kids, strings.TrimSpace(string(args)))
	}
	return kids
}

// envWithout drops variables entirely rather than setting them empty: an empty
// value is still a value, and reading one as "no override" is a decision the
// program under test has to make, not something to paper over here.
func envWithout(env []string, names ...string) []string {
	out := env[:0:0]
	for _, kv := range env {
		drop := false
		for _, name := range names {
			if strings.HasPrefix(kv, name+"=") {
				drop = true
			}
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}

func fileIsExecutable(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitHTTP(t *testing.T, url string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if status(t, url) == http.StatusOK {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("%s never answered within %s", url, within)
}

func status(t *testing.T, url string) int {
	t.Helper()
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func get(t *testing.T, url string) string {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

func tail(s string, lines int) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}
