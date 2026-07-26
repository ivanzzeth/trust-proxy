//go:build tart_e2e

// macOS-only end-to-end coverage, in a tart VM.
//
// What needs a real macOS host and cannot be done in a container: the launchd
// LaunchDaemon (install → runs as root → survives kill -9 via KeepAlive →
// uninstall removes both the plist and the managed binary), and TUN capture,
// which needs the OS's utun and root.
//
// Why a VM and not this machine: installing a LaunchDaemon and switching capture
// to TUN changes system state. The VM has a graphical console, so a mistake that
// cuts SSH is still recoverable; on the developer's own machine it is not.
//
// Run with: make e2e-macos  (skipped unless tart and a running VM are present)
package test

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// vmName is the tart VM these tests drive. Override with TP_TART_VM.
const defaultVM = "macos-base"

func TestMacOSSystemServiceLifecycle(t *testing.T) {
	vm := requireTart(t)
	vm.ship(t)

	dataDir := "/tmp/tp-e2e-service"
	vm.run(t, "pkill -f 'trust-proxy serve' || true")
	vm.sudo(t, "~/trust-proxy service uninstall || true")
	// The data directory belongs to root once the service has run, so a previous
	// run's leftovers need root to clear.
	vm.sudo(t, "rm -rf "+dataDir)

	// A LaunchDaemon must not point inside an .app bundle: trashing the app would
	// leave launchd retrying a missing program at every boot. Install from a path
	// shaped like a bundle and assert the plist points at the managed copy.
	bundle := "~/FakeApp/Trust Proxy.app/Contents/MacOS"
	vm.run(t, "rm -rf ~/FakeApp && mkdir -p '"+bundle+"' && cp ~/trust-proxy '"+bundle+"/trust-proxy'")
	vm.sudo(t, "'"+bundle+"/trust-proxy' service install --data "+dataDir+" --api-addr 127.0.0.1:21585")

	status := vm.out(t, "~/trust-proxy service status --json")
	if !strings.Contains(status, `"program": "/usr/local/libexec/trust-proxy"`) {
		t.Fatalf("the daemon was not pointed at the managed copy:\n%s", status)
	}
	vm.waitAPI(t, "21585")

	uid := strings.TrimSpace(vm.out(t, "ps -o uid= -p $(pgrep -f 'trust-proxy serve' | head -1) | tr -d ' '"))
	if uid != "0" {
		t.Fatalf("the service runs as uid %s, so TUN would be impossible", uid)
	}

	// Trash the app: the daemon keeps working, which is the whole point of the copy.
	vm.run(t, "rm -rf ~/FakeApp")
	vm.sudo(t, "launchctl kickstart -k system/io.trust-proxy.gateway")
	vm.waitAPI(t, "21585")

	// KeepAlive brings it back after a hard kill.
	vm.sudo(t, "kill -9 $(pgrep -f 'trust-proxy serve' | head -1)")
	vm.waitAPI(t, "21585")

	// Uninstall removes the plist, the managed binary and the process.
	vm.sudo(t, "~/trust-proxy service uninstall")
	time.Sleep(3 * time.Second)
	if out := vm.out(t, "test -f /Library/LaunchDaemons/io.trust-proxy.gateway.plist && echo present || echo gone"); !strings.Contains(out, "gone") {
		t.Fatal("the plist outlived uninstall")
	}
	if out := vm.out(t, "test -f /usr/local/libexec/trust-proxy && echo present || echo gone"); !strings.Contains(out, "gone") {
		t.Fatal("the managed binary outlived uninstall")
	}
	if out := vm.out(t, "pgrep -f 'trust-proxy serve' | wc -l | tr -d ' '"); strings.TrimSpace(out) != "0" {
		t.Fatalf("a gateway is still running after uninstall: %s", out)
	}
}

func TestMacOSTUNCaptureWithDeadMansSwitch(t *testing.T) {
	vm := requireTart(t)
	vm.ship(t)

	dataDir := "/tmp/tp-e2e-tun"
	vm.run(t, "pkill -f 'trust-proxy serve' || true")
	vm.sudo(t, "~/trust-proxy service uninstall || true")
	vm.sudo(t, "rm -rf "+dataDir)
	// TUN needs root, which is what the service is for.
	vm.sudo(t, "~/trust-proxy service install --data "+dataDir+" --api-addr 127.0.0.1:21585")
	vm.waitAPI(t, "21585")
	defer func() { vm.sudo(t, "~/trust-proxy service uninstall || true") }()

	// Switch to TUN with a short dead-man's switch and deliberately do not confirm:
	// the gateway must put itself back, which is the guarantee that makes remote
	// TUN switches safe at all.
	vm.run(t, `curl -s -X POST http://127.0.0.1:21585/api/mode -H 'content-type: application/json' -d '{"mode":"tun","guard_seconds":20}'`)
	time.Sleep(4 * time.Second)
	if mode := vm.mode(t, "21585"); mode != "tun" {
		t.Fatalf("mode = %q, want tun (root service should be able to create a utun)", mode)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if vm.mode(t, "21585") == "manual" {
			return // reverted on its own
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("the dead-man's switch never reverted the mode")
}

// ---- harness -------------------------------------------------------------

type tartVM struct{ name, ip string }

// requireTart skips unless tart is installed, the VM exists and is running, and
// ssh works — a missing dependency is not a test failure.
func requireTart(t *testing.T) *tartVM {
	t.Helper()
	if _, err := exec.LookPath("tart"); err != nil {
		t.Skip("tart is not installed")
	}
	if _, err := exec.LookPath("sshpass"); err != nil {
		t.Skip("sshpass is not installed (needed to drive the VM non-interactively)")
	}
	name := envOr("TP_TART_VM", defaultVM)
	out, err := exec.Command("tart", "ip", name).Output()
	if err != nil {
		t.Skipf("tart VM %q is not running: %v", name, err)
	}
	vm := &tartVM{name: name, ip: strings.TrimSpace(string(out))}
	if vm.ip == "" {
		t.Skipf("tart VM %q has no IP yet", name)
	}
	if _, err := vm.try("echo ok"); err != nil {
		t.Skipf("cannot ssh into %s (%s): %v", name, vm.ip, err)
	}
	return vm
}

// ship copies the binary under test into the VM.
func (v *tartVM) ship(t *testing.T) {
	t.Helper()
	bin := buildDarwinBinary(t)
	args := append([]string{"-p", vmPass, "scp"}, v.sshOpts()...)
	args = append(args, bin, "admin@"+v.ip+":~/trust-proxy")
	if out, err := exec.Command("sshpass", args...).CombinedOutput(); err != nil {
		t.Fatalf("ship binary: %v\n%s", err, out)
	}
}

const vmPass = "admin"

// sshOpts multiplex every command over one connection.
//
// One ssh per command exhausts sshd's auth/session limits within a few dozen
// steps — measured: a mid-test command came back "Permission denied
// (publickey,password,keyboard-interactive)" while the same command worked on its
// own. ControlMaster keeps a single authenticated channel open instead.
func (v *tartVM) sshOpts() []string {
	return []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "PubkeyAuthentication=no",
		"-o", "NumberOfPasswordPrompts=1",
		"-o", "ConnectTimeout=10",
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=/tmp/tp-tart-" + v.name,
		"-o", "ControlPersist=120",
	}
}

func (v *tartVM) try(script string) (string, error) {
	args := append([]string{"-p", vmPass, "ssh"}, v.sshOpts()...)
	args = append(args, "admin@"+v.ip, "bash -lc "+shellQuote(script))
	out, err := exec.Command("sshpass", args...).CombinedOutput()
	return string(out), err
}

func (v *tartVM) run(t *testing.T, script string) {
	t.Helper()
	if out, err := v.try(script); err != nil {
		t.Fatalf("vm: %s: %v\n%s", script, err, out)
	}
}

func (v *tartVM) out(t *testing.T, script string) string {
	t.Helper()
	out, _ := v.try(script)
	return out
}

// sudo runs a command as root inside the VM (its admin password is well known;
// this is a throwaway test VM).
func (v *tartVM) sudo(t *testing.T, script string) {
	t.Helper()
	if out, err := v.try("echo " + vmPass + " | sudo -S bash -lc " + shellQuote(script)); err != nil {
		t.Fatalf("vm sudo: %s: %v\n%s", script, err, out)
	}
}

func (v *tartVM) waitAPI(t *testing.T, port string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if out, err := v.try("curl -sf -m 2 http://127.0.0.1:" + port + "/api/health"); err == nil && strings.Contains(out, "ok") {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("the gateway never answered on :%s\n%s", port, v.out(t, "tail -20 /tmp/tp-e2e-*/serve.log 2>/dev/null"))
}

func (v *tartVM) mode(t *testing.T, port string) string {
	t.Helper()
	out := v.out(t, "curl -s -m 3 http://127.0.0.1:"+port+`/api/status | tr ',' '\n' | grep '"mode"' | cut -d'"' -f4`)
	return strings.TrimSpace(out)
}

func buildDarwinBinary(t *testing.T) string {
	t.Helper()
	bin := t.TempDir() + "/trust-proxy"
	cmd := exec.Command("go", "build",
		"-tags", "with_clash_api with_quic with_utls with_gvisor with_wireguard",
		"-o", bin, ".")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build darwin binary: %v\n%s", err, out)
	}
	return bin
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
