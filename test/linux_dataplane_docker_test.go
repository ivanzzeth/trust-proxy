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

// The password lifecycle a real first run goes through.
//
// `install` claims the gateway with a random password it tells nobody — the working
// credential is the API key — and prints "set a console password when you want to
// log in from a browser". So the first `user passwd` is a *set*, and requiring the
// current password there would make the documented next step impossible: the
// current one is 32 random bytes that were never printed.
//
// After that it is a change, and a change has to prove you know the old one, or a
// stolen session is not a session but a takeover. And either way every session the
// old password opened has to end, because "change your password" is the advice
// everyone gives for a stolen session and it needs to be true.
func TestLinuxPasswordLifecycleFromClaimToChange(t *testing.T) {
	l := newLab(t, "tp-e2e-passwd")
	const first = "first-console-password"
	const second = "second-console-password"

	// 1. The first set needs no current password.
	if out := l.exec("printf '" + first + "\\n" + first + "\\n' | trust-proxy user passwd root"); !strings.Contains(out, "password updated") {
		t.Fatalf("the first password set failed, so the step install tells you to run does not work:\n%s", out)
	}
	if out := l.exec("printf '" + first + "\\n' | trust-proxy auth login root"); !strings.Contains(out, "logged in") {
		t.Fatalf("could not log in with the password just set:\n%s", out)
	}

	// 2. Changing it without the current one is refused. Through the CLI, which is
	// the path a person takes: it asks for the current password when the API says it
	// needs one, and with nothing on stdin to answer with, the change cannot happen.
	if out := l.exec("printf '" + second + "\\n" + second + "\\n' | trust-proxy user passwd root 2>&1 || true"); strings.Contains(out, "password updated") {
		t.Fatalf("changing an already-set password went through without the current one:\n%s", out)
	}
	if out := l.exec("printf '" + second + "\\n' | trust-proxy auth login root 2>&1 || true"); strings.Contains(out, "logged in") {
		t.Fatal("the refused change took effect anyway")
	}

	// 3. With it, the change goes through and the old password stops working.
	if out := l.exec("printf '" + second + "\\n" + second + "\\n' | trust-proxy user passwd root --current " + first); !strings.Contains(out, "password updated") {
		t.Fatalf("the change with a correct current password failed:\n%s", out)
	}
	if out := l.exec("printf '" + first + "\\n' | trust-proxy auth login root 2>&1"); strings.Contains(out, "logged in") {
		t.Fatalf("the old password still logs in:\n%s", out)
	}
	if out := l.exec("printf '" + second + "\\n' | trust-proxy auth login root"); !strings.Contains(out, "logged in") {
		t.Fatalf("the new password does not log in:\n%s", out)
	}
	l.assertBoxAlive("after the password lifecycle")
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

// Switching to Split must not depend on being able to reach GitHub.
//
// Split seeds the catalog's *remote* rule sets, and sing-box refuses to start
// when it cannot fetch one — so on a gateway with no exit node that cannot reach
// raw.githubusercontent.com, `posture set split` failed outright, eight lines of
// Go network errors deep. That is the first thing a new user behind the GFW
// tries: no node means the download cannot go through the proxy either, and the
// mirror the catalog has carried all along was never read.
//
// This container reaches nothing, which is the whole point: the posture switch
// has to succeed anyway, with the unreachable sets switched off and named.
func TestLinuxSplitWorksWithNoReachableRuleSetSource(t *testing.T) {
	l := newLab(t, "tp-e2e-split")

	out := l.exec("trust-proxy posture set split -y")
	if strings.Contains(out, "error:") {
		t.Fatalf("switching to Split failed on a machine that cannot download rule sets:\n%s", out)
	}
	if got := l.exec("trust-proxy posture get"); !strings.Contains(got, "split") {
		t.Fatalf("posture did not switch: %s", got)
	}
	l.assertBoxAlive("posture set split with nothing downloadable")

	// Told, not silently degraded: a policy quietly missing a dozen pieces is
	// worse than one that says which pieces and how to get them.
	if !strings.Contains(out, "could not be downloaded") {
		t.Fatalf("the disabled rule sets were not reported to the caller:\n%s", out)
	}
	if !strings.Contains(out, "exit node") {
		t.Fatalf("the message does not say how to fix it:\n%s", out)
	}
	// Disabled, not dropped — the entry stays so it can be turned on later.
	sets := l.exec("trust-proxy rules sets ls")
	if !strings.Contains(sets, "geoip-cn") {
		t.Fatalf("an unreachable rule set was dropped rather than disabled:\n%s", sets)
	}

	// And Split is really in force: the gate is open.
	l.mustReach("Split with no rule sets should still drop the Permit gate")
}

// Password guessing has to be bounded on a real gateway, and bounding it must not
// lock the owner out.
//
// POST /api/auth/login is public and each attempt forces a 19 MiB argon2id
// derivation — on purpose even for a username that does not exist, so an unknown
// account and a wrong password cost the same. There was no limiter of any kind, so
// an anonymous caller could hold as much of that memory as it could open
// connections, and on a single-process gateway running the machine out of memory
// stops forwarding traffic rather than merely breaking the API.
//
// Asserted here rather than only in the handler test because the thing worth
// knowing is that the data plane is still carrying packets afterwards.
func TestLinuxLoginFloodIsRefusedAndTheDataPlaneSurvives(t *testing.T) {
	l := newLab(t, "tp-e2e-throttle")
	l.exec("trust-proxy acl add permit " + originIP + " --type ip")
	l.mustReach("before the flood")

	// Well past the per-minute budget, from one source.
	codes := l.exec(`for i in $(seq 1 25); do ` +
		`curl -s -o /dev/null -w '%{http_code} ' -X POST ` +
		`-H 'Content-Type: application/json' ` +
		`-d '{"username":"nobody","password":"wrong-password-long"}' ` +
		`http://127.0.0.1:21585/api/auth/login; done`)
	if !strings.Contains(codes, "429") {
		t.Fatalf("25 password attempts in a row were all served, so guessing is unbounded "+
			"and so is the argon2 memory behind it:\n%s", codes)
	}
	// The early ones must still have been answered properly — a limiter that refuses
	// from the first attempt is a lockout, not a limit.
	if !strings.Contains(codes, "401") {
		t.Fatalf("no attempt got a real answer; the limiter is refusing everything:\n%s", codes)
	}

	// The point of all of it: traffic is still moving.
	l.mustReach("after a login flood")

	// And a legitimate login still works once the window rolls, because a gateway
	// nobody can log into is the failure this was supposed to prevent.
	l.exec("sleep 61")
	if out := l.exec("trust-proxy auth state --json"); strings.Contains(out, "429") {
		t.Fatalf("the limiter did not release after its window:\n%s", out)
	}
	l.assertBoxAlive("after a login flood")
}

// A posture switch must not delete the DNS policy.
//
// applySlot did `if slot.DNS != nil { … }` with no else, and posture.SeedSplit
// never records DNS, so the first switch to Split applied a zero DNSConfig —
// injectDNS returns early on that and the rebuilt config had no `dns` block at
// all. Gone: the direct-split resolver that keeps domestic sites off an overseas
// edge, fakeip, hosts, DoH-via-proxy. In manual mode that means falling back to
// the system resolver, i.e. resolving in the clear.
//
// It hid twice over. alignLiveStores then tried to write the empty config, the
// store refused it, and the refusal was only logged — so the file still held the
// real policy while the running box had none, and a restart put it back and took
// the evidence with it. Which is why this asserts across a restart as well.
func TestLinuxPostureSwitchKeepsTheDNSPolicy(t *testing.T) {
	l := newLab(t, "tp-e2e-posture-dns")

	// The signal is a loopback stub resolver: whichever resolver gets asked proves
	// which path the query took. It is the technique the selftest uses for the same
	// reason, and here it is the only one that works, because the two obvious
	// alternatives both measure the wrong thing:
	//
	//   - `dns get` reads the *store*, and the store is the half that stayed correct
	//     — alignLiveStores' write of the empty config was refused by validate. A
	//     test against it passes whether or not the bug is present. Measured: it did.
	//   - a `hosts`-type server with a rule pointing at it never sees a direct-routed
	//     name at all, because the split pins the direct outbound to a
	//     domain_resolver, which names a server instead of re-entering dns.rules.
	//
	// So: a resolver on 127.0.0.1:5353 that answers one name, and `final` pointing
	// at it. If the dns block survives the posture switch the name resolves; if the
	// block is gone, sing-box falls back to the system resolver and the name does
	// not exist anywhere.
	const marker = "posture-dns-probe.invalid"
	l.exec(`cat > /tmp/stub.py <<'EOF'
import socket, struct
IP = bytes(int(x) for x in "` + originIP + `".split("."))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 5353))
while True:
    data, addr = s.recvfrom(2048)
    open("/tmp/stub.queries", "ab").write(data[12:40] + b"\n")
    # id | flags QR+RD+RA | qd=1 an=1 ns=0 ar=0 | question echoed | A answer
    resp = data[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00" + data[12:]
    resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + IP
    s.sendto(resp, addr)
EOF`)
	l.exec("setsid nohup python3 /tmp/stub.py >/dev/null 2>&1 < /dev/null &")
	l.exec(`cat > /tmp/dns.json <<'EOF'
{"servers":[{"tag":"stub","type":"udp","server":"127.0.0.1","port":5353}],
 "final":"stub","disable_direct_split":true}
EOF`)
	if out := l.exec("trust-proxy dns set -f /tmp/dns.json"); strings.Contains(out, "error:") {
		t.Fatalf("could not establish a DNS policy to preserve:\n%s", out)
	}
	// Permit the name, so the Permit gate is not what decides this either way.
	l.exec("trust-proxy acl add permit " + marker)

	reaches := func() bool {
		return strings.Contains(
			l.exec(`curl -s -m 6 -x http://127.0.0.1:21584 http://`+marker+`/ 2>&1 || true`), "ORIGIN-OK")
	}
	settled := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		if reaches() {
			settled = true
			break
		}
		time.Sleep(time.Second)
	}
	if !settled {
		t.Fatalf("the stub resolver is not being used even before the posture switch, so this test "+
			"would measure nothing.\ndns get:\n%s\nstub queries: %s\nlog:\n%s",
			l.exec("trust-proxy dns get"),
			l.exec("wc -c /tmp/stub.queries 2>/dev/null || echo none"),
			l.exec("tail -6 /var/lib/trust-proxy/serve.log"))
	}

	if out := l.exec("trust-proxy posture set split -y"); strings.Contains(out, "error:") {
		t.Fatalf("switching to Split failed:\n%s", out)
	}
	l.assertBoxAlive("posture set split")

	if !reaches() {
		t.Fatalf("the posture switch deleted the DNS policy: %s no longer resolves, so the stub "+
			"is not being asked.\ndns get still says:\n%s\n(that divergence between the store and the "+
			"running config is the second half of the bug)", marker, l.exec("trust-proxy dns get"))
	}
	// And live/disk must agree, which is the half that used to heal itself on
	// restart and take the evidence with it.
	if got := l.exec("trust-proxy posture get --json"); strings.Contains(got, `"diverged_stores": [`) {
		t.Fatalf("a store refused the applied policy, so the console and the gateway disagree:\n%s", got)
	}

	l.exec("systemctl restart trust-proxy")
	l.waitAPI("21585")
	if !reaches() {
		t.Fatalf("the DNS policy did not survive a restart after a posture switch:\n%s",
			l.exec("trust-proxy dns get"))
	}
	l.assertBoxAlive("after restart following a posture switch")
}
