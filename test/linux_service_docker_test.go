//go:build docker_e2e

// Linux service lifecycle, for real, under a real systemd.
//
// The unit renderer has unit tests, but "the file looks right" is not the claim
// that matters — the claim is that a machine which runs one command comes back
// after a reboot with the gateway running, TUN included, its owner able to use
// the CLI without pasting anything, and one command removing every trace. That
// needs an init system, so it runs in a privileged container with systemd as
// pid 1.
//
// Run with: make e2e-linux   (needs docker; skipped otherwise)
package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// consoleNone is what the e2e binary needs: it is built without the UI embedded
// (embedding it would drag pnpm into a Go test), and `install` refuses such a
// binary rather than producing a service whose every page says "dashboard not
// built". That refusal is asserted below; everywhere else the flag says "yes, an
// API-only gateway is what I want".
const consoleNone = " --console none"

func TestLinuxSystemdServiceLifecycle(t *testing.T) {
	requireDocker(t)
	img := buildSystemdImage(t)
	bin := buildLinuxBinary(t)

	c := &systemdBox{t: t, name: "tp-e2e-systemd", image: img, binary: bin}
	c.boot()

	// ---- what a machine looks like before anything is installed ------------
	// `env` is the one thing the desktop shell asks, so it has to be answerable
	// with nothing installed and (as far as it is concerned) nothing running.
	if out := c.exec("trust-proxy env"); !strings.Contains(out, "/var/lib/trust-proxy") {
		t.Fatalf("`env` should name the machine-wide data dir:\n%s", out)
	}
	if out := c.exec("trust-proxy env"); !strings.Contains(out, "installed=false") {
		t.Fatalf("`env` should report nothing installed yet:\n%s", out)
	}

	// A binary with no console in it must not become a service that serves
	// "dashboard not built" on every page. Refusing is the whole point.
	if out := c.exec("trust-proxy install"); !strings.Contains(out, "no console built into it") {
		t.Fatalf("install accepted a binary with no console:\n%s", out)
	}
	if got := c.exec("test -f /etc/systemd/system/trust-proxy.service && echo present || echo gone"); !strings.Contains(got, "gone") {
		t.Fatal("a refused install left a unit behind")
	}

	// Policy from a pre-refactor per-user install must survive the upgrade: this
	// is somebody's subscription list, and starting from an empty store would read
	// as "the install wiped my config".
	c.exec(`mkdir -p /root/.trust-proxy && echo '{"domains":["adopted.example"]}' > /root/.trust-proxy/whitelist.json`)

	// ---- install: one command, and the machine is set up -------------------
	out := c.exec("trust-proxy install --api-addr 127.0.0.1:21585" + consoleNone)
	if !strings.Contains(out, "/etc/systemd/system/trust-proxy.service") {
		t.Fatalf("install did not report the unit path:\n%s", out)
	}
	// The machine-wide directory, not a home directory: a boot-time daemon starts
	// before anyone logs in, and a root daemon writing into a home is what left
	// people with a directory their own desktop app could not write.
	if !strings.Contains(out, "data:    /var/lib/trust-proxy") {
		t.Fatalf("service should use the machine-wide data dir:\n%s", out)
	}
	// The daemon must run its own copy, never the binary it was installed from —
	// that copy is what keeps a moved or deleted file from bricking every boot.
	if !strings.Contains(out, "program: /usr/local/libexec/trust-proxy") {
		t.Fatalf("service does not run the managed copy:\n%s", out)
	}
	if !strings.Contains(out, "adopted") {
		t.Fatalf("the old per-user policy was not adopted:\n%s", out)
	}
	if got := c.exec("cat /var/lib/trust-proxy/whitelist.json"); !strings.Contains(got, "adopted.example") {
		t.Fatalf("the adopted whitelist did not arrive: %s", got)
	}
	if got := c.exec("cat /root/.trust-proxy/whitelist.json"); !strings.Contains(got, "adopted.example") {
		t.Fatal("adoption moved the old data instead of copying it")
	}

	c.waitAPI("21585")
	if got := c.exec("systemctl is-active trust-proxy.service"); !strings.Contains(got, "active") {
		t.Fatalf("service is not active: %q", got)
	}
	// Enabled, or it does not come back after a reboot — the entire point.
	if got := c.exec("systemctl is-enabled trust-proxy.service"); !strings.Contains(got, "enabled") {
		t.Fatalf("service is not enabled at boot: %q", got)
	}
	if got := c.exec("trust-proxy service status"); !strings.Contains(got, "running:    true") {
		t.Fatalf("`service status` disagrees with systemd:\n%s", got)
	}

	// ---- the install claimed it, and the CLI just works --------------------
	// This is the half that used to be left to the user: an installed gateway they
	// then had to claim, log in to, and export a key for before a single command
	// worked. Nothing below sets TP_API_KEY or passes --api-token.
	if !strings.Contains(out, "claimed as") {
		t.Fatalf("install did not claim the gateway:\n%s", out)
	}
	creds := "/root/.config/trust-proxy/credentials.json"
	if got := c.exec("test -f " + creds + " && echo present || echo gone"); !strings.Contains(got, "present") {
		t.Fatalf("the API key was not left where its owner can read it (%s)", creds)
	}
	if perm := strings.TrimSpace(c.exec("stat -c %a " + creds)); perm != "600" {
		t.Fatalf("the credential is not private: mode %s", perm)
	}
	if got := c.exec("trust-proxy auth whoami"); !strings.Contains(got, "admin") {
		t.Fatalf("the CLI is not authenticated straight after install:\n%s", got)
	}
	if got := c.exec("trust-proxy status"); strings.Contains(got, "unauthorized") {
		t.Fatalf("a plain CLI command needed a credential nobody was given:\n%s", got)
	}
	// The desktop shell's way in: a key becomes a one-time URL that carries a
	// session. No GUI needed to prove the mechanism works.
	ticket := strings.TrimSpace(c.exec("trust-proxy auth ticket"))
	if !strings.HasPrefix(ticket, "http://") {
		t.Fatalf("`auth ticket` did not mint a console URL: %q", ticket)
	}
	if got := c.exec(`curl -s -o /dev/null -w '%{http_code}' -m 5 '` + ticket + `'`); !strings.Contains(got, "302") {
		t.Fatalf("following a ticket should redirect into the console, got %q", got)
	}
	// Single use: the second visit must not hand out another session.
	if got := c.exec(`curl -s -o /dev/null -w '%{http_code}' -m 5 '` + ticket + `'`); strings.Contains(got, "302") {
		t.Fatal("a console ticket was accepted twice")
	}

	// ---- what a desktop app would be told to do ----------------------------
	// The shell renders one of four offers straight from `env`. Getting this wrong
	// is invisible: it shows a window that looks right.
	if got := c.exec("trust-proxy env --json"); !strings.Contains(got, `"action": "attach"`) {
		t.Fatalf("with its own service running and current, the app should just attach:\n%s", got)
	}
	if got := c.exec("trust-proxy env --json"); !strings.Contains(got, `"managed": true`) {
		t.Fatalf("the running gateway is the managed copy and must say so:\n%s", got)
	}
	// The upgrade case, played by a differently-stamped binary — which is exactly
	// what a newly downloaded app is. Without this the new app attaches to the old
	// daemon, shows its console, and nothing anywhere says the update did nothing.
	newer := buildLinuxBinaryVersioned(t, "v99.0.0-newer")
	c.copyIn(newer, "/usr/local/bin/trust-proxy-newer")
	got := c.exec("trust-proxy-newer env --json")
	if !strings.Contains(got, `"action": "update"`) {
		t.Fatalf("a newer app looking at an older daemon must be told to update:\n%s", got)
	}
	if !strings.Contains(got, `"stale": true`) {
		t.Fatalf("the version mismatch was not detected:\n%s", got)
	}

	// ---- `serve` is not the user-facing command any more --------------------
	// Running it unprivileged used to quietly produce a second, TUN-less gateway
	// in a home directory. Now it says what to run instead.
	c.exec("useradd -m nobody2 || true")
	if got := c.exec("su nobody2 -c 'trust-proxy serve' 2>&1 | head -5"); !strings.Contains(got, "install") {
		t.Fatalf("an unprivileged `serve` should point at `install`:\n%s", got)
	}

	// ---- it survives a hostile death --------------------------------------
	pid := strings.TrimSpace(c.exec("systemctl show -p MainPID --value trust-proxy.service"))
	c.exec("kill -9 " + pid + " || true")
	deadline := time.Now().Add(30 * time.Second)
	var back string
	for time.Now().Before(deadline) {
		back = strings.TrimSpace(c.exec("systemctl show -p MainPID --value trust-proxy.service"))
		if back != "" && back != "0" && back != pid && strings.Contains(c.exec("systemctl is-active trust-proxy.service"), "active") {
			break
		}
		time.Sleep(time.Second)
	}
	if back == pid || back == "" || back == "0" {
		t.Fatalf("service did not come back after kill -9 (pid %q → %q)", pid, back)
	}

	// ---- TUN, the reason a service exists at all ---------------------------
	// Reinstalling in TUN mode is also the "replace an existing unit" path, which
	// must not leave two jobs behind. Deliberately *without* --takeover: re-running
	// install is how you change the mode or upgrade the binary, and the gateway in
	// the way is our own service. Refusing here made the most ordinary maintenance
	// command fail on the machine it was maintaining.
	if out := c.exec("trust-proxy install --api-addr 127.0.0.1:21585 --mode tun -y" + consoleNone); !strings.Contains(out, "mode:    tun") {
		t.Fatalf("TUN install did not pin the mode:\n%s", out)
	}
	c.waitAPI("21585")
	// Through the CLI, with the credential install left behind — a bare curl now
	// gets 401, which is the point of claiming it.
	status := c.exec("trust-proxy status --json")
	if !strings.Contains(status, `"mode": "tun"`) {
		t.Fatalf("gateway did not come up in TUN mode: %s", status)
	}
	// The capability flag the console uses to decide whether to even offer TUN.
	// It is what makes the console's TUN switch work at all, and it is true here
	// only because the gateway is the root service rather than somebody's process.
	if !strings.Contains(status, `"can_tun": true`) {
		t.Fatalf("a root gateway on Linux must report can_tun: %s", status)
	}
	if out := c.exec("trust-proxy service status"); !strings.Contains(out, "running:    true") {
		t.Fatalf("the reinstalled service is not running:\n%s", out)
	}
	// Re-claiming must not happen: the gateway already has an owner, and a second
	// install quietly minting another admin would be a way in.
	if n := strings.Count(c.exec("trust-proxy user ls --json"), `"username"`); n != 1 {
		t.Fatalf("the second install should not have created another account, found %d", n)
	}
	if links := c.exec("ip -o link show"); !strings.Contains(links, "tun") {
		t.Fatalf("TUN mode is active but no tun interface exists:\n%s", links)
	}
	// An interface existing is not the claim — capture is. So: reach for a
	// non-local address and require that it entered through tun and was refused by
	// default-deny.
	//
	// Non-local matters. A destination on the container's own subnet leaves via the
	// attached link route, below sing-box's policy rules, and never touches the
	// tunnel — measured, and exactly the trap the fleet test documents. Asserting
	// on such an address would pass whether or not TUN worked at all.
	c.exec("curl -s -m 5 -o /dev/null http://203.0.113.7/ || true")
	time.Sleep(2 * time.Second)
	log := c.exec("grep 203.0.113.7 /var/lib/trust-proxy/serve.log || true")
	if !strings.Contains(log, "inbound/tun") {
		t.Fatalf("a non-local connection was not captured by tun:\n%s", log)
	}
	if !strings.Contains(log, "blocked") {
		t.Fatalf("TUN captured the connection but default-deny did not refuse it:\n%s", log)
	}

	// ---- the mode has to outlive a restart and an upgrade ------------------
	// This whole block was missing, and its absence is why the bug shipped: every
	// assertion above passes `--mode tun` explicitly, so nothing here ever asked
	// what happens to a machine that was *left* in TUN.
	//
	// The mode used to live only in the systemd unit's --mode argument. Two ways to
	// lose it, both silent — service active, console green, `status` reporting a
	// healthy gateway that is not capturing anything:
	//   1. switch modes from the console/CLI (which does not touch the unit), then
	//      restart;
	//   2. re-install without --mode, which rewrites the unit without it — and a
	//      bare `trust-proxy install` is the documented upgrade path, what
	//      scripts/install.sh runs, and what the desktop Update button runs.
	if out := c.exec("systemctl show -p ExecStart trust-proxy"); strings.Contains(out, "--mode") {
		t.Fatalf("the unit pins a capture mode, so rewriting it can silently change one:\n%s", out)
	}
	c.exec("systemctl restart trust-proxy")
	c.waitAPI("21585")
	if status := c.exec("trust-proxy status --json"); !strings.Contains(status, `"mode": "tun"`) {
		t.Fatalf("TUN did not survive a service restart: %s\nunit: %s",
			status, c.exec("systemctl show -p ExecStart trust-proxy"))
	}
	// The upgrade path, verbatim: same command, no --mode.
	if out := c.exec("trust-proxy install -y" + consoleNone); !strings.Contains(out, "mode:    tun") {
		t.Fatalf("a bare re-install did not report the mode it was leaving in place:\n%s", out)
	}
	c.waitAPI("21585")
	if status := c.exec("trust-proxy status --json"); !strings.Contains(status, `"mode": "tun"`) {
		t.Fatalf("upgrading turned TUN off: %s", status)
	}
	if links := c.exec("ip -o link show"); !strings.Contains(links, "tun") {
		t.Fatalf("no tun interface after the upgrade, so capture really did stop:\n%s", links)
	}

	// An unconfirmed guarded switch must NOT be recorded.
	//
	// The guard is a dead-man's switch: if the new mode cuts off your access you
	// never get to confirm, and it reverts. Recording it the moment it applies would
	// defeat that for the one case it exists for — a machine that hard-crashes
	// during the guard window would boot straight back into the mode that locked you
	// out, since the revert never got to run. So the store keeps the last mode that
	// was actually known good.
	c.exec("trust-proxy mode set manual -y --guard 3")
	time.Sleep(6 * time.Second)
	if status := c.exec("trust-proxy status --json"); !strings.Contains(status, `"mode": "tun"`) {
		t.Fatalf("an unconfirmed guarded switch did not revert: %s", status)
	}
	c.exec("systemctl restart trust-proxy")
	c.waitAPI("21585")
	if status := c.exec("trust-proxy status --json"); !strings.Contains(status, `"mode": "tun"`) {
		t.Fatalf("an unconfirmed guarded switch was recorded anyway, so a crash during the "+
			"guard window boots into the mode the guard was protecting you from: %s", status)
	}

	// Confirming makes it durable — that is what confirming means.
	c.exec("trust-proxy mode set manual -y --guard 30")
	c.exec("trust-proxy mode confirm")
	c.exec("systemctl restart trust-proxy")
	c.waitAPI("21585")
	if status := c.exec("trust-proxy status --json"); !strings.Contains(status, `"mode": "manual"`) {
		t.Fatalf("a confirmed switch to manual did not survive a restart, so the stored mode is "+
			"being overridden on boot instead of read: %s", status)
	}
	// Back to TUN for the assertions that follow. No guard: an unguarded switch is
	// settled the moment it succeeds.
	c.exec("trust-proxy mode set tun -y --guard 0")
	c.waitAPI("21585")
	if status := c.exec("trust-proxy status --json"); !strings.Contains(status, `"mode": "tun"`) {
		t.Fatalf("could not get back into TUN: %s", status)
	}

	// ---- installing over a gateway somebody started by hand ----------------
	// Refusing is the default: installing while another gateway holds the API port
	// produced a service that could never bind and was retried at every boot, with
	// the machine looking fine because the other gateway answered.
	c.exec("trust-proxy uninstall")
	c.exec("rm -rf /var/lib/trust-proxy /root/.trust-proxy /root/.config/trust-proxy")
	c.exec("trust-proxy serve --daemon --data /root/.trust-proxy" + consoleNone)
	c.waitAPI("21585")

	// A gateway that is not the managed copy must read as "take it over", not as
	// something to attach to. Attaching is how a machine kept its hand-started
	// gateway forever and never got a service installed.
	if got := c.exec("trust-proxy env --json"); !strings.Contains(got, `"action": "takeover"`) {
		t.Fatalf("a hand-started gateway should be offered for takeover:\n%s", got)
	}
	if out := c.exec("trust-proxy install --mode tun -y" + consoleNone); !strings.Contains(out, "already listening") {
		t.Fatalf("installing over a running gateway must refuse:\n%s", out)
	}
	if got := c.exec("test -d /var/lib/trust-proxy && echo yes || echo no"); strings.Contains(got, "yes") {
		t.Fatal("a refused install must not have copied data first — that is a half-done install")
	}
	// Delete the pid file first. Takeover used to depend on one, which is not
	// guaranteed — a `serve` in a terminal never writes one, and a *previous failed
	// takeover* deleted the one that did exist, so every retry had one less way to
	// find the process. Measured on a real machine: it sent the user back to a
	// command line, which is the thing the desktop app exists to remove.
	c.exec("rm -f /root/.trust-proxy/serve.pid")
	takeover := c.exec("trust-proxy install --mode tun -y --takeover" + consoleNone)
	if !strings.Contains(takeover, "reported by the gateway itself") {
		t.Fatalf("with no pid file, takeover must ask the gateway who it is:\n%s", takeover)
	}
	if !strings.Contains(takeover, "/etc/systemd/system/trust-proxy.service") {
		t.Fatalf("--takeover should stop the gateway in the way and install:\n%s", takeover)
	}
	c.waitAPI("21585")
	// Two gateways on one machine is the failure this whole command exists to
	// prevent: they fight over cache.db's single-writer lock and over the ports,
	// and the one you are looking at is not necessarily the one enforcing policy.
	if procs := strings.TrimSpace(c.exec("ps -eo args | grep '[t]rust-proxy serve' | wc -l")); procs != "1" {
		t.Fatalf("exactly one gateway should be left, got %s:\n%s\n--- install output ---\n%s",
			procs, c.exec("ps -eo args | grep '[t]rust-proxy serve'"), takeover)
	}

	// ---- an unclaimed gateway is not open to the network -------------------
	// The synthetic admin an empty registry hands out used to ignore where the
	// request came from, and the one-time claim code only ever guarded the
	// bootstrap endpoint — so an exposed, not-yet-claimed gateway belonged to
	// whoever scanned the port first.
	c.exec("trust-proxy uninstall")
	c.exec("rm -rf /var/lib/trust-proxy /root/.config/trust-proxy")
	if out := c.exec("trust-proxy install --api-addr 0.0.0.0:21585 --no-claim" + consoleNone); !strings.Contains(out, "installed") {
		t.Fatalf("install on a wildcard address failed:\n%s", out)
	}
	c.waitAPI("21585")
	ip := strings.TrimSpace(c.exec("hostname -I | awk '{print $1}'"))
	if ip == "" {
		t.Fatal("could not find the container's own non-loopback address")
	}
	if code := strings.TrimSpace(c.exec(`curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST http://` + ip + `:21585/api/mode`)); code != "401" {
		t.Fatalf("an unclaimed gateway answered an admin write from the network: HTTP %s", code)
	}
	if code := strings.TrimSpace(c.exec(`curl -s -o /dev/null -w '%{http_code}' -m 5 http://` + ip + `:21585/api/subscriptions`)); code != "401" {
		t.Fatalf("an unclaimed gateway served its subscriptions to the network: HTTP %s", code)
	}
	// What must still work, or a remote console could only ever show a form that
	// 403s, and the machine itself could never be set up.
	if code := strings.TrimSpace(c.exec(`curl -s -o /dev/null -w '%{http_code}' -m 5 http://` + ip + `:21585/api/auth/state`)); code != "200" {
		t.Fatalf("/api/auth/state must stay reachable off-loopback: HTTP %s", code)
	}
	if code := strings.TrimSpace(c.exec(`curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST http://127.0.0.1:21585/api/mode -d '{}'`)); code == "401" {
		t.Fatal("an unclaimed gateway must still be usable from the machine it runs on")
	}

	// ---- uninstall leaves nothing behind ----------------------------------
	c.exec("trust-proxy uninstall")
	time.Sleep(2 * time.Second)
	for _, probe := range []struct{ desc, cmd, want string }{
		{"unit file", "test -f /etc/systemd/system/trust-proxy.service && echo present || echo gone", "gone"},
		{"managed binary", "test -f /usr/local/libexec/trust-proxy && echo present || echo gone", "gone"},
		{"the job", "systemctl is-active trust-proxy.service || true", "inactive"},
		// Policy is the user's, not the installer's: uninstalling a service must
		// never be how someone loses their subscriptions and rules.
		{"the data", "test -f /var/lib/trust-proxy/config.json && echo kept || echo lost", "kept"},
	} {
		if got := c.exec(probe.cmd); !strings.Contains(got, probe.want) {
			t.Fatalf("after uninstall, %s: got %q, want %q", probe.desc, strings.TrimSpace(got), probe.want)
		}
	}
}

// systemdBox is a container running systemd as pid 1.
type systemdBox struct {
	t      *testing.T
	name   string
	image  string
	binary string
}

func (c *systemdBox) boot() {
	c.t.Helper()
	_ = exec.Command("docker", "rm", "-f", c.name).Run()
	// Registered before the log dump, so it runs *after* it: cleanups are LIFO,
	// and a `defer c.remove()` in the test body would run earlier still. That is
	// how the first failing run of this suite reported "No such container"
	// instead of the journal that would have explained it.
	c.t.Cleanup(c.remove)
	args := []string{
		"run", "-d", "--name", c.name,
		// systemd needs to own a cgroup tree, and TUN needs the device.
		"--privileged", "--cgroupns=host",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		"-v", c.binary + ":/usr/local/bin/trust-proxy:ro",
		c.image,
	}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		c.t.Skipf("cannot run a privileged systemd container here: %v\n%s", err, out)
	}
	c.t.Cleanup(c.dumpOnFailure)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		state := c.exec("systemctl is-system-running || true")
		if strings.Contains(state, "running") || strings.Contains(state, "degraded") {
			return
		}
		time.Sleep(time.Second)
	}
	c.t.Fatalf("systemd never became ready in %s", c.name)
}

// waitAPI blocks until the gateway inside the container answers, so a later
// assertion cannot fail merely because it arrived first.
func (c *systemdBox) waitAPI(port string) {
	c.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(c.exec(`curl -s -m 2 http://127.0.0.1:`+port+`/api/health || true`), `"ok"`) {
			return
		}
		time.Sleep(time.Second)
	}
	c.t.Fatalf("gateway API on :%s never answered\n%s",
		port, c.exec("journalctl -u trust-proxy.service --no-pager | tail -30 || true"))
}

// copyIn puts a file inside the running container (the binary under test is a
// read-only bind mount, so a second one has to be copied rather than mounted).
func (c *systemdBox) copyIn(src, dst string) {
	c.t.Helper()
	if out, err := exec.Command("docker", "cp", src, c.name+":"+dst).CombinedOutput(); err != nil {
		c.t.Fatalf("docker cp %s: %v\n%s", src, err, out)
	}
	c.exec("chmod 0755 " + dst)
}

func (c *systemdBox) exec(sh string) string {
	c.t.Helper()
	out, _ := exec.Command("docker", "exec", c.name, "bash", "-c", sh).CombinedOutput()
	return string(out)
}

func (c *systemdBox) dumpOnFailure() {
	if !c.t.Failed() {
		return
	}
	c.t.Logf("--- journal ---\n%s", c.exec("journalctl -u trust-proxy.service --no-pager | tail -40 || true"))
	c.t.Logf("--- serve.log ---\n%s", c.exec("tail -40 /var/lib/trust-proxy/serve.log || true"))
}

func (c *systemdBox) remove() {
	_ = exec.Command("docker", "rm", "-f", c.name).Run()
}

// buildSystemdImage builds a Debian image with systemd as pid 1. Skips (rather
// than fails) when the base image cannot be fetched — no network, or a docker
// credential helper that is not installed — because that is the environment's
// problem, not a defect in what is being tested.
func buildSystemdImage(t *testing.T) string {
	t.Helper()
	const tag = "trust-proxy-systemd-test"
	dir := t.TempDir()
	dockerfile := `FROM debian:12
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        systemd systemd-sysv dbus curl iproute2 procps python3 && \
    rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "build", "-q", "-t", tag, dir).CombinedOutput()
	if err != nil {
		t.Skipf("cannot build the systemd test image: %v\n%s", err, out)
	}
	return tag
}

// Every command that rewrites policy rebuilds the sing-box config, and a config
// the box refuses is a gateway that stops enforcing anything. The service
// lifecycle test above covers install and uninstall; it exercises none of that
// surface — about twenty commands, all uncovered, until one of them shipped
// broken: switching to Split emitted a rule-set http_client pointing at a DNS
// server that only exists in some configurations, so `posture set split` failed
// on every fresh install and nothing in this repo noticed.
//
// So: walk the surface. Each step changes policy, then asserts the gateway is
// still up *and* that its last rebuild actually produced a running box —
// "reverted" is a survivable failure and an invisible one, because the API
// returns an error while the console keeps showing the old, working state.
func TestLinuxPolicyRebuilds(t *testing.T) {
	requireDocker(t)
	img := buildSystemdImage(t)
	bin := buildLinuxBinary(t)

	c := &systemdBox{t: t, name: "tp-e2e-policy", image: img, binary: bin}
	c.boot()
	if out := c.exec("trust-proxy install" + consoleNone); !strings.Contains(out, "installed") {
		t.Fatalf("install failed:\n%s", out)
	}
	c.waitAPI("21585")

	// A node to route to, imported rather than fetched: this container has no
	// route to the internet and the point is the config rebuild, not the network.
	const node = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@203.0.113.9:8388#e2e-node"
	if out := c.exec("printf '%s' '" + node + "' | trust-proxy sub import --name e2e"); !strings.Contains(out, "1 nodes") {
		t.Fatalf("importing a node failed:\n%s", out)
	}
	subID := strings.TrimSpace(c.exec(`trust-proxy sub ls | awk 'NR==2{print $1}'`))
	if subID == "" {
		t.Fatal("no subscription id back from `sub ls`")
	}

	for _, step := range []struct {
		what string
		cmd  string
		// want is a substring the *verification* command must produce; verify is
		// how to read the change back. Reading it back matters: an API that
		// accepted a change and a gateway that applied it are different claims,
		// and this whole suite exists because of the gap between them.
		verify, want string
	}{
		{"apply a subscription", "trust-proxy sub apply " + subID, "trust-proxy proxies ls", "e2e-node"},
		{"permit a domain", "trust-proxy acl add permit example.com", "trust-proxy acl ls permit", "example.com"},
		{"permit an ip", "trust-proxy acl add permit 198.51.100.7 --type ip", "trust-proxy acl ls permit", "198.51.100.7"},
		{"deny a domain", "trust-proxy acl add deny ads.example", "trust-proxy acl ls deny", "ads.example"},
		{"bypass a domain", "trust-proxy acl add no-proxy intranet.example", "trust-proxy acl ls no-proxy", "intranet.example"},
		{"remove a permit", "trust-proxy acl rm permit example.com", "trust-proxy acl ls permit", "198.51.100.7"},
		{"a custom rule", "trust-proxy rules custom add corp.example --egress direct", "trust-proxy rules custom ls", "corp.example"},
		{"the direct resolver", "trust-proxy dns set --direct-server 119.29.29.29", "trust-proxy dns get", "119.29.29.29"},
		{"routing mode Global", "trust-proxy routing set Global -y", "trust-proxy routing get", "Global"},
		{"routing mode Rule", "trust-proxy routing set Rule -y", "trust-proxy routing get", "Rule"},
		{"the final route", "trust-proxy final set direct", "trust-proxy final get", "direct"},
		{"capture mode tun", "trust-proxy mode set tun --guard 0 -y", "trust-proxy status", "mode:              tun"},
		{"capture mode manual", "trust-proxy mode set manual --guard 0 -y", "trust-proxy status", "mode:              manual"},
		{"save a profile", "trust-proxy profile save e2e-snapshot", "trust-proxy profile ls", "e2e-snapshot"},
	} {
		out := c.exec(step.cmd)
		if strings.Contains(out, "error:") {
			t.Fatalf("%s: %s\n%s", step.what, step.cmd, out)
		}
		if got := c.exec(step.verify); !strings.Contains(got, step.want) {
			t.Fatalf("%s: %q did not show %q\n%s", step.what, step.verify, step.want, got)
		}
		c.assertBoxAlive(step.what)
	}

	// Activating a saved profile is a single atomic rebuild of everything at once
	// — the widest config change there is, and the one most likely to produce
	// something the box rejects.
	profID := strings.TrimSpace(c.exec(`trust-proxy profile ls | awk '/e2e-snapshot/{print $1}'`))
	if profID != "" {
		if out := c.exec("trust-proxy profile activate " + profID); strings.Contains(out, "error:") {
			t.Fatalf("activating a profile failed:\n%s", out)
		}
		c.assertBoxAlive("profile activate")
	}

	// Split seeds the catalog's *remote* rule sets, so it cannot fully succeed in
	// a container with no route to the internet. What it must never do is fail for
	// a reason of our own making: a reference to a DNS server nothing creates, or
	// a detour naming the plain direct outbound. Both shipped, both looked exactly
	// like this, and both are invisible to every other test in this repo.
	out := c.exec("trust-proxy posture set split -y")
	for _, ours := range []string{"domain resolver not found", "makes no sense", "missing", "unknown"} {
		if strings.Contains(out, ours) {
			t.Fatalf("switching to Split built a config the box rejects (%q):\n%s", ours, out)
		}
	}
	if strings.Contains(out, "error:") && !strings.Contains(out, "initial rule-set") {
		t.Fatalf("Split failed for something other than the unreachable .srs download:\n%s", out)
	}
	c.assertBoxAlive("posture set split")
}

// assertBoxAlive checks the gateway is answering *and* still has a data plane.
//
// The API surviving is not the claim: it is served by the process, not by the
// box, so a rebuild that fails after closing the previous instance leaves a
// responsive console in front of nothing. The inbound listener is the honest
// signal — either traffic can still reach the gateway or it cannot.
//
// Deliberately not a grep for the "no running box" line: that message is emitted
// the moment a rebuild fails and stays in the log afterwards, so it also fires
// for a failure that then rolled back successfully — which is the *designed*
// behaviour and not something to fail a test over. Measured: it reported a dead
// gateway while 21584 was listening the whole time.
func (c *systemdBox) assertBoxAlive(after string) {
	c.t.Helper()
	if !strings.Contains(c.exec(`curl -s -m 3 http://127.0.0.1:21585/api/health || true`), `"ok"`) {
		c.t.Fatalf("after %s: the gateway stopped answering", after)
	}
	if !strings.Contains(c.exec("ss -ltn || true"), ":21584") {
		c.t.Fatalf("after %s: the API answers but the proxy inbound is gone — "+
			"a rebuild left the console in front of no data plane:\n%s",
			after, c.exec("tail -20 /var/lib/trust-proxy/serve.log"))
	}
}
