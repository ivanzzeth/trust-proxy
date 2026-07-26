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
	cliAPI    = "22585"
	adminPass = "gateway-admin-password"
	userPass  = "laptop-console-password"
	proxyPass = "laptop-proxy-password"
)

func TestFleetGatewayAsExit(t *testing.T) {
	requireDocker(t)
	bin := buildLinuxBinary(t)

	// Two networks, and the origin sits on the far one. The gateway straddles both;
	// the client is only on the near one.
	//
	// This topology is the test: with everything on one network the origin resolves
	// to an RFC1918 address, the client's own LAN bypass sends it direct, and an
	// assertion that "the chain carried the request" passes without the gateway
	// being involved at all. Measured — the first version of this test did exactly
	// that, and the gateway's attribution came from an unrelated health-check probe.
	// Here a direct attempt cannot resolve or reach the origin, so success means the
	// gateway carried it.
	net := "tp-e2e-" + fmt.Sprint(os.Getpid())
	far := net + "-far"
	run(t, "docker", "network", "create", net)
	run(t, "docker", "network", "create", far)
	t.Cleanup(func() {
		_ = exec.Command("docker", "network", "rm", net).Run()
		_ = exec.Command("docker", "network", "rm", far).Run()
	})

	// ---- origin: on the far network only ------------------------------------
	origin := container{t: t, name: net + "-origin"}
	origin.start("--network", far, "busybox", "sh", "-c",
		"mkdir -p /www && echo REACHED-THE-ORIGIN > /www/index.html && httpd -f -p 80 -h /www")

	// A second origin, deliberately not permitted: the request/approve loop below
	// has to make a real destination reachable, or "it still fails" cannot tell
	// "policy refused it" from "the name does not exist".
	origin2 := container{t: t, name: net + "-origin2"}
	origin2.start("--network", far, "busybox", "sh", "-c",
		"mkdir -p /www && echo REACHED-THE-SECOND-ORIGIN > /www/index.html && httpd -f -p 80 -h /www")

	// ---- gateway: owns the policy, requires a credential -------------------
	// No -c: each container seeds the shipped default config into its own data
	// directory, which is what a real install does. Hand-writing one here is how the
	// first version of this test ended up without a catch-all rule — and therefore
	// without default-deny — while asserting nothing about it.
	gw := container{t: t, name: net + "-gateway"}
	gw.start("--network", net, "-v", bin+":/trust-proxy:ro",
		"alpine", "/trust-proxy", "serve", "--data", "/data",
		"--api-addr", "0.0.0.0:"+gwAPI, "--dump-config", "/data/merged.json")
	// Attach the gateway to the far network too: it is the only route to the origin.
	run(t, "docker", "network", "connect", far, gw.name)
	gw.waitAPI(gwAPI)

	// The shipped default binds the proxy inbound to loopback — right for a laptop,
	// wrong for a gateway that serves other machines. Widen it the way an operator
	// would (edit the config, restart) rather than by hand-writing a whole config.
	gw.mustExec("sh", "-c",
		`sed -i 's/"listen": "127.0.0.1"/"listen": "0.0.0.0"/' /data/config.json`)
	gw.restart()
	gw.waitAPI(gwAPI)

	// Claiming it from inside the container is loopback, so no bootstrap code is
	// needed — the headless path the design promises.
	gw.exec("sh", "-c", "printf '"+adminPass+"\\n' | /trust-proxy auth bootstrap root --api-addr 127.0.0.1:"+gwAPI)
	key := loginKey(gw, "root", adminPass, gwAPI)
	_ = strings.TrimSpace(gw.execOut("sh", "-c",
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
	cli.start("--network", net, "-v", bin+":/trust-proxy:ro",
		"alpine", "/trust-proxy", "serve", "--data", "/data",
		"--api-addr", "0.0.0.0:"+cliAPI, "--dump-config", "/data/merged.json")
	cli.waitAPI(cliAPI)

	cliCLI := func(args ...string) string {
		return cli.mustExec(append(append([]string{"/trust-proxy"}, args...), "--api-addr", "127.0.0.1:"+cliAPI)...)
	}
	cliCLI("node", "add", "cloud", "http://"+gw.name+":"+gwAPI)
	cliCLI("node", "exit", "cloud", "--port", gwProxy, "--user", "laptop", "--password", proxyPass)
	// Client mode: this machine captures traffic and hands it to the gateway, which
	// is the only thing that decides what may leave. Without it the client's own
	// default-deny would block first, and every client machine would have to carry a
	// copy of the policy — the thing sharing a gateway is supposed to avoid.
	cliCLI("node", "mode", "client")
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

	// ---- a direct attempt must be impossible, or the next assertion is empty
	direct := cli.execOut("sh", "-c",
		"wget -q -T 5 -O - http://"+origin.name+"/ 2>&1; echo rc=$?")
	if strings.Contains(direct, "REACHED-THE-ORIGIN") {
		t.Fatalf("the client can reach the origin without the gateway, so this test proves nothing:\n%s", direct)
	}

	// ---- the actual point: traffic goes client -> gateway -> origin --------
	// BusyBox wget with http_proxy: the mixed inbound speaks HTTP proxy as well as
	// socks, so the container needs nothing installed — and a test that apk-installs
	// curl fails on a machine with no route to the package mirror.
	body := cli.execOut("sh", "-c",
		"env http_proxy=http://127.0.0.1:"+gwProxy+" wget -q -T 15 -O - http://"+origin.name+"/ 2>&1")
	if !strings.Contains(body, "REACHED-THE-ORIGIN") {
		t.Fatalf("the chain did not carry the request; got %q\nclient log:\n%s\ngateway log:\n%s",
			body, cli.logs(), gw.logs())
	}

	// ---- the client's own record names the exit that carried it ------------
	//
	// A group name ("selector/proxy") is not an answer when several exits are in
	// play, so the record must resolve to the member in use.
	cliHist := cliCLI("history", "ls", "--json", "--limit", "10")
	if !strings.Contains(cliHist, "gw-cloud") {
		t.Fatalf("the client's history does not name the exit it used:\n%s", cliHist)
	}

	// ---- and the gateway attributed it to that account --------------------
	time.Sleep(2 * time.Second)
	hist := gwCLI("history", "ls", "--json")
	if !strings.Contains(hist, `"usr":"laptop"`) && !strings.Contains(hist, `"usr": "laptop"`) {
		t.Fatalf("the gateway did not attribute the connection to laptop:\n%s", hist)
	}

	// ---- blocked upstream -> ask -> approved -> works ----------------------
	//
	// A client cannot widen the gateway's policy, so the only honest recourse is to
	// ask. The request travels as a disabled rule and approval is the admin enabling
	// it; this walks the whole loop and proves the traffic changes state.
	wanted := origin2.name
	before := cli.execOut("sh", "-c",
		"env http_proxy=http://127.0.0.1:"+gwProxy+" wget -q -T 8 -O - http://"+wanted+"/ 2>&1")
	if strings.Contains(before, "REACHED-THE-SECOND-ORIGIN") {
		t.Fatalf("a destination the gateway never permitted was reachable:\n%s", before)
	}

	// The client asks, with its own account on the gateway (creating a request is
	// the only write a client has).
	laptopKey := loginKey(gw, "laptop", userPass, gwAPI)
	asked := gw.mustExec("env", "TP_API_KEY="+laptopKey, "/trust-proxy",
		"request", "ask", wanted, "--reason", "needed for work", "--api-addr", "127.0.0.1:"+gwAPI)
	if !strings.Contains(asked, "pending") {
		t.Fatalf("the request was not accepted: %s", asked)
	}

	// A pending request must not itself permit anything.
	stillBlocked := cli.execOut("sh", "-c",
		"env http_proxy=http://127.0.0.1:"+gwProxy+" wget -q -T 8 -O - http://"+wanted+"/ 2>&1")
	if strings.Contains(stillBlocked, "REACHED-THE-SECOND-ORIGIN") {
		t.Fatalf("a pending request opened the destination before approval:\n%s", stillBlocked)
	}

	// The admin sees who asked and why…
	pending := gwCLI("request", "ls", "--json")
	if !strings.Contains(pending, "laptop") || !strings.Contains(pending, "needed for work") {
		t.Fatalf("the admin cannot see the request:\n%s", pending)
	}
	// …and a client cannot approve its own request.
	selfApprove := gw.execOut("env", "TP_API_KEY="+laptopKey, "/trust-proxy",
		"request", "approve", requestID(t, pending), "--api-addr", "127.0.0.1:"+gwAPI)
	if !strings.Contains(selfApprove, "error") {
		t.Fatalf("a client approved its own request:\n%s", selfApprove)
	}

	// The admin approves, and the destination opens.
	gwCLI("request", "approve", requestID(t, pending))
	time.Sleep(2 * time.Second)
	after := cli.execOut("sh", "-c",
		"env http_proxy=http://127.0.0.1:"+gwProxy+" wget -q -T 10 -O - http://"+wanted+"/ 2>&1")
	if !strings.Contains(after, "REACHED-THE-SECOND-ORIGIN") {
		t.Fatalf("approval did not open the destination:\n%s\ngateway log:\n%s", after, gw.logs())
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

// restart bounces the container, so a config edit takes effect the way it would
// for an operator.
func (c *container) restart() {
	c.t.Helper()
	run(c.t, "docker", "restart", c.name)
}

func (c *container) logs() string {
	out, _ := exec.Command("docker", "logs", "--tail", "120", c.name).CombinedOutput()
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

// requestID pulls the first rule id out of `request ls --json`.
func requestID(t *testing.T, jsonOut string) string {
	t.Helper()
	var rules []struct{ ID string }
	if err := json.Unmarshal([]byte(jsonOut), &rules); err != nil || len(rules) == 0 {
		t.Fatalf("cannot read a request id from:\n%s", jsonOut)
	}
	return rules[0].ID
}

// loginKey logs in inside the container and returns the API key it prints.
func loginKey(c container, user, pass, api string) string {
	c.t.Helper()
	out := c.mustExec("sh", "-c",
		"printf '"+pass+"\n' | /trust-proxy auth login "+user+" --api-addr 127.0.0.1:"+api+" --json")
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, `"key"`) {
			continue
		}
		parts := strings.Split(line, `"`)
		if len(parts) >= 4 {
			return parts[len(parts)-2]
		}
	}
	c.t.Fatalf("no API key in the login output for %s:\n%s", user, out)
	return ""
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

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}
