package proxygen

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenCommandOmitsEmptyFlagsAndQuotesInput(t *testing.T) {
	got := GenCommand(Options{Type: "vless-reality", Server: "203.0.113.9", Port: 443})
	want := "trust-proxy proxy gen --type vless-reality --server 203.0.113.9 --port 443"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	// A node name is free text; unquoted it would split into extra arguments.
	got = GenCommand(Options{Type: "trojan", Server: "a.example", Port: 8443, Name: "my exit; rm -rf /"})
	if !strings.Contains(got, `--name 'my exit; rm -rf /'`) {
		t.Fatalf("name not quoted: %s", got)
	}
}

// The script carries the generated config, so the server that ends up running is
// the one the client node was minted against.
func TestInstallScriptIsRunnableShellCarryingTheConfig(t *testing.T) {
	res, err := Generate(Options{Type: "shadowsocks", Server: "203.0.113.9", Port: 8388})
	if err != nil {
		t.Fatal(err)
	}
	script := InstallScript(res.Server, "")
	if !strings.Contains(script, "trust-proxy proxy run -c server.json -d") {
		t.Fatalf("script does not start the server:\n%s", script)
	}

	// Run it with a stub `trust-proxy` on PATH: the config must land on disk
	// unmangled (shadowsocks keys are base64 and contain shell metacharacters).
	dir := t.TempDir()
	bin := filepath.Join(dir, "trust-proxy")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), "PATH="+dir+":/usr/bin:/bin")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}

	var back map[string]any
	raw, err := os.ReadFile(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("written config is not valid JSON: %v\n%s", err, raw)
	}
	want, _ := json.Marshal(res.Server)
	got, _ := json.Marshal(back)
	if string(want) != string(got) {
		t.Fatalf("config round-trip differs:\n got %s\nwant %s", got, want)
	}
}
