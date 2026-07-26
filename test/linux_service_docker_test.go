//go:build docker_e2e

// Linux service lifecycle, for real, under a real systemd.
//
// The unit renderer has unit tests, but "the file looks right" is not the claim
// that matters — the claim is that a machine which installs this comes back after
// a reboot with the gateway running, TUN included, and that one command removes
// every trace. That needs an init system, so it runs in a privileged container
// with systemd as pid 1.
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

func TestLinuxSystemdServiceLifecycle(t *testing.T) {
	requireDocker(t)
	img := buildSystemdImage(t)
	bin := buildLinuxBinary(t)

	c := &systemdBox{t: t, name: "tp-e2e-systemd", image: img, binary: bin}
	c.boot()
	defer c.remove()

	// ---- install ----------------------------------------------------------
	out := c.exec("trust-proxy service install --api-addr 127.0.0.1:21585")
	if !strings.Contains(out, "/etc/systemd/system/trust-proxy.service") {
		t.Fatalf("install did not report the unit path:\n%s", out)
	}
	// The machine-wide directory, not a home directory: a boot-time daemon starts
	// before anyone logs in.
	if !strings.Contains(out, "--data /var/lib/trust-proxy") {
		t.Fatalf("service should default to the machine-wide data dir:\n%s", out)
	}
	// The daemon must run its own copy, never the binary it was installed from —
	// that copy is what keeps a moved or deleted file from bricking every boot.
	if !strings.Contains(out, "program: /usr/local/libexec/trust-proxy") {
		t.Fatalf("service does not run the managed copy:\n%s", out)
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
	// must not leave two jobs behind.
	if out := c.exec("trust-proxy service install --api-addr 127.0.0.1:21585 --mode tun -y"); !strings.Contains(out, "--mode tun") {
		t.Fatalf("TUN install did not pin the mode:\n%s", out)
	}
	c.waitAPI("21585")
	status := c.exec(`curl -s -m 3 http://127.0.0.1:21585/api/status`)
	if !strings.Contains(status, `"mode":"tun"`) {
		t.Fatalf("gateway did not come up in TUN mode: %s", status)
	}
	// The capability flag the console uses to decide whether to even offer TUN.
	if !strings.Contains(status, `"can_tun":true`) {
		t.Fatalf("a root gateway on Linux must report can_tun: %s", status)
	}
	if links := c.exec("ip -o link show"); !strings.Contains(links, "tun") {
		t.Fatalf("TUN mode is active but no tun interface exists:\n%s", links)
	}

	// ---- uninstall leaves nothing behind ----------------------------------
	c.exec("trust-proxy service uninstall")
	time.Sleep(2 * time.Second)
	for _, probe := range []struct{ desc, cmd, want string }{
		{"unit file", "test -f /etc/systemd/system/trust-proxy.service && echo present || echo gone", "gone"},
		{"managed binary", "test -f /usr/local/libexec/trust-proxy && echo present || echo gone", "gone"},
		{"the job", "systemctl is-active trust-proxy.service || true", "inactive"},
		// Policy is the user's, not the installer's: uninstalling a service must
		// never be how someone loses their subscriptions and rules.
		{"the data", "test -f /var/lib/trust-proxy/whitelist.json && echo kept || echo lost", "kept"},
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
        systemd systemd-sysv dbus curl iproute2 procps && \
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
