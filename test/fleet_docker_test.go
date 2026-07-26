//go:build docker_e2e

// Package test holds end-to-end tests that need containers.
//
// This one covers the multi-gateway shape the project exists for: a gateway
// somewhere else holds the shared policy, and a local machine pushes its traffic
// through it with its own account. Doing it by hand across two hosts is how it
// was verified first, and that is not repeatable — so it lives here.
//
// Three containers on a private network, no internet needed:
//
//	origin   busybox httpd, the thing being fetched
//	gateway  trust-proxy: holds the policy, requires a proxy credential
//	client   trust-proxy: no policy of its own, exits through `gateway`
//
// Run with: make e2e-fleet   (needs docker; skipped otherwise)
package test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	gwAPI     = "21585"
	gwProxy   = "21584"
	gwClash   = "21586"
	cliAPI    = "22585"
	cliProxy  = "22584"
	cliClash  = "22586"
	adminPass = "gateway-admin-password"
	userPass  = "laptop-console-password"
	proxyPass = "laptop-proxy-password"
)

func TestFleetGatewayAsExit(t *testing.T) {
	requireDocker(t)
	bin := buildLinuxBinary(t)

	net := "tp-e2e-" + fmt.Sprint(os.Getpid())
	run(t, "docker", "network", "create", net)
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", net).Run() })

	// ---- origin: what the client will fetch --------------------------------
	origin := container{t: t, name: net + "-origin"}
	origin.start("--network", net, "busybox", "sh", "-c",
		"mkdir -p /www && echo REACHED-THE-ORIGIN > /www/index.html && httpd -f -p 80 -h /www")

	// ---- gateway: owns the policy, requires a credential -------------------
	gw := container{t: t, name: net + "-gateway"}
	gwCfg := writeConfig(t, "gateway", gwProxy, gwClash, "0.0.0.0")
	gw.start("--network", net, "-v", bin+":/trust-proxy:ro", "-v", gwCfg+":/config.json:ro",
		"alpine", "/trust-proxy", "serve", "-c", "/config.json", "--data", "/data",
		"--api-addr", "0.0.0.0:"+gwAPI, "--clash-addr", "127.0.0.1:"+gwClash)
	gw.waitAPI(gwAPI)

	// Claiming it from inside the container is loopback, so no bootstrap code is
	// needed — the headless path the design promises.
	gw.exec("sh", "-c", "printf '"+adminPass+"\\n' | /trust-proxy auth bootstrap root --api-addr 127.0.0.1:"+gwAPI)
	key := strings.TrimSpace(gw.execOut("sh", "-c",
		"printf '"+adminPass+"\\n' | /trust-proxy auth login root --api-addr 127.0.0.1:"+gwAPI+" --json | grep -o '\"key\": *\"[^\"]*\"' | cut -d'\"' -f4"))
	if !strings.HasPrefix(key, "tp_") {
		t.Fatalf("did not get an API key from login: %q", key)
	}
	// Any CLI step that fails must fail the test here, not three assertions later:
	// the first version of this swallowed a wrong argument list and the failure
	// surfaced as "the chain did not carry the request", which is a much worse
	// error message than "acl add: accepts 2 args".
	gwCLI := func(args ...string) string {
		full := append([]string{"env", "TP_API_KEY=" + key, "/trust-proxy"}, args...)
		return gw.mustExec(append(full, "--api-addr", "127.0.0.1:"+gwAPI)...)
	}
	// An account for the client machine, with a proxy password, and a policy that
	// permits the origin. The client will hold none of this.
	gwCLI("user", "add", "laptop", "--password", userPass)
	gwCLI("user", "proxy-pass", "laptop", "--password", proxyPass)
	gwCLI("acl", "add", "permit", origin.name, "--type", "domain")

	// ---- client: no policy, exits through the gateway ---------------------
	cli := container{t: t, name: net + "-client"}
	cliCfg := writeConfig(t, "client", cliProxy, cliClash, "0.0.0.0")
	cli.start("--network", net, "-v", bin+":/trust-proxy:ro", "-v", cliCfg+":/config.json:ro",
		"alpine", "/trust-proxy", "serve", "-c", "/config.json", "--data", "/data",
		"--api-addr", "0.0.0.0:"+cliAPI, "--clash-addr", "127.0.0.1:"+cliClash)
	cli.waitAPI(cliAPI)

	cliCLI := func(args ...string) string {
		return cli.mustExec(append(append([]string{"/trust-proxy"}, args...), "--api-addr", "127.0.0.1:"+cliAPI)...)
	}
	cliCLI("node", "add", "cloud", "http://"+gw.name+":"+gwAPI)
	cliCLI("node", "exit", "cloud", "--port", gwProxy, "--user", "laptop", "--password", proxyPass)
	// The client permits the origin locally too: its own default-deny is upstream
	// of the gateway's, so both have to allow it. (Client mode, which drops the
	// local gate entirely, is the next step.)
	cliCLI("acl", "add", "permit", origin.name, "--type", "domain")
	// Point the catch-all straight at the gateway, so the test exercises the exit
	// rather than urltest's opinion of it (the health check probes the internet,
	// which this network deliberately does not have).
	cliCLI("final", "set", "gw-cloud")
	time.Sleep(3 * time.Second)

	// ---- the exit joined the proxy group without any new mechanism ---------
	proxies := cliCLI("proxies", "ls", "--json")
	if !strings.Contains(proxies, "gw-cloud") {
		t.Fatalf("the gateway did not become a proxy-group member:\n%s", proxies)
	}

	// ---- the actual point: traffic goes client -> gateway -> origin --------
	// BusyBox wget with http_proxy: the mixed inbound speaks HTTP proxy as well as
	// socks, so the container needs nothing installed — and a test that apk-installs
	// curl fails on a machine with no route to the package mirror.
	body := cli.execOut("sh", "-c",
		"env http_proxy=http://127.0.0.1:"+cliProxy+" wget -q -T 15 -O - http://"+origin.name+"/ 2>&1")
	if !strings.Contains(body, "REACHED-THE-ORIGIN") {
		t.Fatalf("the chain did not carry the request; got %q\nclient log:\n%s\ngateway log:\n%s",
			body, cli.logs(), gw.logs())
	}

	// ---- and the gateway attributed it to that account --------------------
	time.Sleep(2 * time.Second)
	hist := gwCLI("history", "ls", "--json")
	if !strings.Contains(hist, `"usr":"laptop"`) && !strings.Contains(hist, `"usr": "laptop"`) {
		t.Fatalf("the gateway did not attribute the connection to laptop:\n%s", hist)
	}

	// ---- a client without the credential must not get through -------------
	unauth := cli.execOut("sh", "-c",
		"env http_proxy=http://"+gw.name+":"+gwProxy+" wget -q -T 10 -O - http://"+origin.name+"/ 2>&1; echo rc=$?")
	if strings.Contains(unauth, "REACHED-THE-ORIGIN") {
		t.Fatalf("the gateway served a client that presented no credential:\n%s", unauth)
	}
	// …and the same request *with* the credential does get through, which is what
	// makes the line above a real check rather than a broken URL.
	withCred := cli.execOut("sh", "-c",
		"env http_proxy=http://laptop:"+proxyPass+"@"+gw.name+":"+gwProxy+" wget -q -T 15 -O - http://"+origin.name+"/ 2>&1")
	if !strings.Contains(withCred, "REACHED-THE-ORIGIN") {
		t.Fatalf("a credentialed client could not reach the origin through the gateway:\n%s\ngateway log:\n%s", withCred, gw.logs())
	}
}

// ---- helpers -------------------------------------------------------------

type container struct {
	t    *testing.T
	name string
}

func (c *container) start(args ...string) {
	c.t.Helper()
	full := append([]string{"run", "-d", "--name", c.name}, args...)
	run(c.t, "docker", full...)
	c.t.Cleanup(func() {
		if c.t.Failed() {
			c.t.Logf("--- %s logs ---\n%s", c.name, c.logs())
		}
		_ = exec.Command("docker", "rm", "-f", c.name).Run()
	})
}

func (c *container) exec(args ...string) {
	c.t.Helper()
	run(c.t, "docker", append([]string{"exec", c.name}, args...)...)
}

func (c *container) execOut(args ...string) string {
	c.t.Helper()
	out, _ := exec.Command("docker", append([]string{"exec", c.name}, args...)...).CombinedOutput()
	return string(out)
}

// mustExec runs a command in the container and fails the test unless it succeeded.
func (c *container) mustExec(args ...string) string {
	c.t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", c.name}, args...)...).CombinedOutput()
	body := string(out)
	if err != nil || strings.Contains(body, "error:") {
		c.t.Fatalf("%s: %s: %v\n%s", c.name, strings.Join(args, " "), err, body)
	}
	return body
}

func (c *container) logs() string {
	out, _ := exec.Command("docker", "logs", "--tail", "40", c.name).CombinedOutput()
	return string(out)
}

// waitAPI blocks until the gateway answers, so the test fails on a real problem
// rather than on a race with startup.
func (c *container) waitAPI(port string) {
	c.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		out := c.execOut("/trust-proxy", "status", "--api-addr", "127.0.0.1:"+port, "--json")
		if strings.Contains(out, "\"mode\"") {
			return
		}
		time.Sleep(time.Second)
	}
	c.t.Fatalf("%s never came up:\n%s", c.name, c.logs())
}

func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not available")
	}
}

// buildLinuxBinary compiles a static linux binary for the container's arch.
func buildLinuxBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "trust-proxy")
	cmd := exec.Command("go", "build",
		"-tags", "with_clash_api with_quic with_utls with_gvisor",
		"-o", bin, ".")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build linux binary: %v\n%s", err, out)
	}
	// The bind mount has to be executable inside the container.
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// writeConfig produces a minimal gateway config: one mixed inbound plus the Clash
// API the console reads. Everything else the gateway injects at runtime.
func writeConfig(t *testing.T, role, port, clash, listen string) string {
	t.Helper()
	cfg := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "mixed-in", "listen": listen, "listen_port": atoi(port),
		}},
		"outbounds": []any{
			map[string]any{"type": "selector", "tag": "proxy", "outbounds": []any{"direct"}, "default": "direct"},
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "blocked"},
		},
		"route": map[string]any{"rules": []any{map[string]any{"action": "sniff"}}},
		"experimental": map[string]any{
			"clash_api":  map[string]any{"external_controller": "127.0.0.1:" + clash},
			"cache_file": map[string]any{"enabled": true, "path": "/data/cache.db"},
		},
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), role+".json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}
