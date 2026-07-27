//go:build docker_e2e

// What the gateway actually *does* to traffic, on a real Linux install.
//
// The other suites check that commands succeed and that the service comes back:
// necessary, and not the product. The product is a claim about packets — that an
// unlisted destination cannot leave, that Deny beats Permit, that a route
// decision never opens the gate — and none of that was asserted anywhere outside
// `selftest`, which builds its own minimal config and runs on a developer's
// machine rather than through an installed service.
//
// Every assertion here goes through the real inbound (:21584) of a
// systemd-managed gateway, against an origin the container can actually reach.
//
// The origin lives on 203.0.113.10 — TEST-NET-3 on `lo`. It has to be *outside*
// RFC1918: private CIDRs are inside the permit set whenever the gate is open, so
// an origin on the container's own subnet would be reachable no matter what the
// policy said, and every test below would pass while proving nothing.
//
// Run with: make e2e-dataplane   (needs docker; skipped otherwise)
package test

import (
	"strings"
	"testing"
	"time"
)

// originIP is TEST-NET-3: routable inside the container once added to lo, and
// not private, so the Permit gate applies to it.
const originIP = "203.0.113.10"

type lab struct{ *systemdBox }

func newLab(t *testing.T, name string) *lab {
	t.Helper()
	requireDocker(t)
	c := &systemdBox{t: t, name: name, image: buildSystemdImage(t), binary: buildLinuxBinary(t)}
	c.boot()
	l := &lab{c}
	l.exec("ip addr add " + originIP + "/32 dev lo || true")
	l.exec("mkdir -p /srv/o && echo ORIGIN-OK > /srv/o/index.html")
	l.exec("cd /srv/o && setsid nohup python3 -m http.server 80 --bind " + originIP + " >/dev/null 2>&1 < /dev/null &")
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(l.exec("curl -s -m 2 http://"+originIP+"/ || true"), "ORIGIN-OK") {
			break
		}
		time.Sleep(time.Second)
	}
	if !strings.Contains(l.exec("curl -s -m 2 http://"+originIP+"/ || true"), "ORIGIN-OK") {
		t.Fatal("the test origin never came up; every assertion below would be meaningless")
	}
	if out := l.exec("trust-proxy install" + consoleNone); !strings.Contains(out, "installed") {
		t.Fatalf("install failed:\n%s", out)
	}
	l.waitAPI("21585")
	return l
}

// through fetches the origin *through the gateway's own inbound*, which is the
// only path where policy applies. A direct curl would prove nothing.
func (l *lab) through() string {
	return l.exec("curl -s -m 6 -x socks5h://127.0.0.1:21584 http://" + originIP + "/ 2>&1 || true")
}

// settle waits for the hot reload a policy change triggers, then reports what
// the data plane does. Polling rather than sleeping: a fixed sleep is either
// flaky or slow, and here it would be both.
func (l *lab) settle(want bool) bool {
	l.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(l.through(), "ORIGIN-OK") == want {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func (l *lab) mustReach(what string) {
	l.t.Helper()
	if !l.settle(true) {
		l.t.Fatalf("%s: the origin should be reachable through the gateway, got %q", what, l.through())
	}
}

func (l *lab) mustBlock(what string) {
	l.t.Helper()
	if !l.settle(false) {
		l.t.Fatalf("%s: the origin should NOT be reachable through the gateway, but it is", what)
	}
}

// The security model, asserted on packets rather than on config.
func TestLinuxDefaultDenyAndTheTwoAxes(t *testing.T) {
	l := newLab(t, "tp-e2e-dataplane")

	// The whole premise: nothing leaves until something says it may.
	l.mustBlock("a fresh install")

	l.exec("trust-proxy acl add permit " + originIP + " --type ip")
	l.mustReach("after permitting the destination")

	// Deny is a floor, not a peer: it wins wherever it disagrees with Permit.
	l.exec("trust-proxy acl add deny " + originIP + " --type ip")
	l.mustBlock("deny must beat permit")
	l.exec("trust-proxy acl rm deny " + originIP + " --type ip")
	l.mustReach("after removing the deny")

	// **Route never opens the gate.** no-proxy decides *where* permitted traffic
	// goes; it must not decide *whether* it may go. Conflating the two axes is the
	// mistake this project's design exists to prevent, so it gets an assertion
	// rather than a paragraph.
	l.exec("trust-proxy acl rm permit " + originIP + " --type ip")
	l.mustBlock("with the permit removed")
	l.exec("trust-proxy acl add no-proxy " + originIP + " --type ip")
	if !l.settle(false) {
		t.Fatal("no-proxy opened the Permit gate — Route and Permit are supposed to be orthogonal")
	}
	l.exec("trust-proxy acl rm no-proxy " + originIP + " --type ip")
}

// Global routing mode is the documented way to bypass default-deny — and the
// safety floor has to survive it, or "Global" would mean "off".
func TestLinuxGlobalModeBypassesTheGateButNotTheFloor(t *testing.T) {
	l := newLab(t, "tp-e2e-global")

	l.mustBlock("Rule mode, nothing permitted")

	l.exec("trust-proxy routing set Global -y")
	l.mustReach("Global mode should let unlisted traffic out")

	// The floor is what makes Global survivable: threat intel, the blacklist and
	// the process/device gates all live below it.
	l.exec("trust-proxy acl add deny " + originIP + " --type ip")
	l.mustBlock("deny must still apply in Global mode")

	l.exec("trust-proxy acl rm deny " + originIP + " --type ip")
	l.exec("trust-proxy routing set Rule -y")
	l.mustBlock("back in Rule mode, default-deny returns")
}

// The dead-man's switch. Switching capture mode on a remote machine can cut the
// connection you are switching it from; the guard is what makes that recoverable
// without physical access, so it is worth an end-to-end assertion rather than a
// unit test of the timer.
func TestLinuxGuardedModeSwitchRevertsItself(t *testing.T) {
	l := newLab(t, "tp-e2e-guard")

	before := strings.TrimSpace(l.exec(`trust-proxy mode get --json | tr ',' '\n' | grep '"mode"' | cut -d'"' -f4`))
	if before == "" {
		t.Fatal("could not read the starting mode")
	}
	if out := l.exec("trust-proxy mode set tun --guard 5 -y"); strings.Contains(out, "error:") {
		t.Fatalf("guarded switch to tun failed:\n%s", out)
	}
	if got := l.exec("trust-proxy status"); !strings.Contains(got, "mode:              tun") {
		t.Fatalf("the switch did not take:\n%s", got)
	}
	// Deliberately never confirm.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(l.exec("trust-proxy status"), "mode:              "+before) {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("the guard never reverted the mode back to %s — a bad switch on a remote box would be permanent", before)
}

// Policy is not policy if it does not survive the machine. A restart is the
// cheap version of a reboot, and it exercises the same path: the stores are
// re-read from disk and the config is rebuilt from them.
func TestLinuxPolicySurvivesRestartAndUpgrade(t *testing.T) {
	l := newLab(t, "tp-e2e-persist")

	l.exec("trust-proxy acl add permit " + originIP + " --type ip")
	l.exec("trust-proxy acl add deny blocked.example")
	l.mustReach("after permitting")

	l.exec("systemctl restart trust-proxy.service")
	l.waitAPI("21585")
	if got := l.exec("trust-proxy acl ls permit"); !strings.Contains(got, originIP) {
		t.Fatalf("the permit list did not survive a restart:\n%s", got)
	}
	if got := l.exec("trust-proxy acl ls deny"); !strings.Contains(got, "blocked.example") {
		t.Fatalf("the deny list did not survive a restart:\n%s", got)
	}
	l.mustReach("after a restart")

	// Re-running install is the upgrade path, and the thing people fear about an
	// upgrade is losing their configuration to it.
	if out := l.exec("trust-proxy install" + consoleNone); !strings.Contains(out, "installed") {
		t.Fatalf("re-installing over the running service failed:\n%s", out)
	}
	l.waitAPI("21585")
	if got := l.exec("trust-proxy acl ls permit"); !strings.Contains(got, originIP) {
		t.Fatalf("an in-place upgrade lost the policy:\n%s", got)
	}
	if n := strings.Count(l.exec("trust-proxy user ls --json"), `"username"`); n != 1 {
		t.Fatalf("an in-place upgrade should not touch the accounts, found %d", n)
	}
	l.mustReach("after an in-place upgrade")
}

// Logging in again rotates this machine's stored key. The old one must stop
// working — otherwise every login leaves another live admin credential on the
// account, which is what the previous behaviour did.
func TestLinuxLoginRotatesTheStoredKey(t *testing.T) {
	l := newLab(t, "tp-e2e-key")

	const pw = "e2e-password-1234"
	l.exec("printf '" + pw + "\\n" + pw + "\\n' | trust-proxy user passwd root")
	creds := "/root/.config/trust-proxy/credentials.json"
	oldKey := strings.TrimSpace(l.exec(`python3 -c "import json;print(json.load(open('` + creds + `'))['gateways']['127.0.0.1:21585']['key'])"`))
	if !strings.HasPrefix(oldKey, "tp_") {
		t.Fatalf("no stored key to start from: %q", oldKey)
	}

	if out := l.exec("printf '" + pw + "\\n' | trust-proxy auth login root"); !strings.Contains(out, "logged in") {
		t.Fatalf("login failed:\n%s", out)
	}
	newKey := strings.TrimSpace(l.exec(`python3 -c "import json;print(json.load(open('` + creds + `'))['gateways']['127.0.0.1:21585']['key'])"`))
	if newKey == oldKey {
		t.Fatal("logging in did not rotate the stored key")
	}
	// The CLI works with the new one…
	if got := l.exec("trust-proxy auth whoami"); !strings.Contains(got, "root") {
		t.Fatalf("the rotated key does not work:\n%s", got)
	}
	// …and the one it replaced is gone, not merely unused.
	got := l.exec(`curl -s -o /dev/null -w '%{http_code}' -m 5 -H "Authorization: Bearer ` + oldKey + `" http://127.0.0.1:21585/api/users`)
	if strings.TrimSpace(got) != "401" {
		t.Fatalf("the previous key still authenticates (HTTP %s) — every login would leave another live admin credential", strings.TrimSpace(got))
	}
}

// A fresh install must not query every domain in the clear.
//
// The default resolver used to be the system one, alone: the ISP saw every
// domain you then proxied, a censored domain answered with a poisoned address
// that got dialed through the exit, and the "DNS follows route" machinery never
// engaged because it only splits away from a resolver behind the proxy. Nothing
// said so, and every install started that way.
//
// Asserted on a box with no route to the internet on purpose: the point is that
// the default is safe *and* still starts. A default that leaks is a bug; a
// default that bricks an offline machine is a worse one.
func TestLinuxFreshInstallResolvesThroughTheExit(t *testing.T) {
	l := newLab(t, "tp-e2e-dns")

	got := l.exec("trust-proxy dns get")
	final := ""
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "final:") {
			final = strings.Fields(line)[1]
		}
	}
	if final == "" {
		t.Fatalf("no final resolver in:\n%s", got)
	}
	var detour string
	for _, line := range strings.Split(got, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == final {
			detour = f[len(f)-1]
		}
	}
	if detour != "proxy" {
		t.Fatalf("the default final resolver %q has detour %q — a fresh install queries in the clear:\n%s",
			final, detour, got)
	}
	// And the direct split is on, so domestic destinations are not resolved from
	// wherever the exit happens to be — the 15-second-taobao failure.
	if !strings.Contains(got, "split on") {
		t.Fatalf("the direct-route split is off, so direct-routed domains resolve through the exit:\n%s", got)
	}
	// Safe is only half of it: the box has to come up with this config on a
	// machine that cannot reach 1.1.1.1.
	l.assertBoxAlive("a fresh install's default DNS")
}

// An install that predates the DNS default change has to heal when it upgrades.
//
// Changing the default only helps machines with no dns.json, and the ones that
// need it are already running with a file that says "resolve everything with the
// system resolver". Without this they would keep querying every proxied domain
// in the clear after upgrading, and nothing would say so.
//
// The other half matters just as much: a config somebody actually chose must
// survive. LAN-only and air-gapped deployments want the system resolver, and
// healing them would be breaking them.
func TestLinuxUpgradeHealsTheOldDNSDefault(t *testing.T) {
	l := newLab(t, "tp-e2e-dnsmig")

	// Put the abandoned default back and restart, as an upgrade from an older
	// version would find it.
	l.exec(`systemctl stop trust-proxy.service`)
	l.exec(`cat > /var/lib/trust-proxy/dns.json <<'JSON'
{"servers":[{"tag":"local","type":"local"}],"rules":[],"final":"local"}
JSON`)
	l.exec(`systemctl start trust-proxy.service`)
	l.waitAPI("21585")

	got := l.exec("trust-proxy dns get")
	if !strings.Contains(got, "final: doh") || !strings.Contains(got, "proxy") {
		t.Fatalf("upgrading left the old leaking default in place:\n%s", got)
	}
	l.assertBoxAlive("healing the old DNS default")

	// Now a deliberate choice of the system resolver: it must be left alone.
	l.exec(`systemctl stop trust-proxy.service`)
	l.exec(`cat > /var/lib/trust-proxy/dns.json <<'JSON'
{"servers":[{"tag":"local","type":"local"}],"rules":[],"final":"local","strategy":"prefer_ipv4"}
JSON`)
	l.exec(`systemctl start trust-proxy.service`)
	l.waitAPI("21585")
	if got := l.exec("trust-proxy dns get"); !strings.Contains(got, "final: local") {
		t.Fatalf("a configured system-resolver setup was overwritten:\n%s", got)
	}
	l.assertBoxAlive("respecting a chosen system resolver")
}
