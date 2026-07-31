//go:build docker_e2e

// TUN capture of *forwarded* traffic — the nftables (auto_redirect) path.
//
// This is a different claim from the one `e2e-linux` already checks, and the
// difference is the whole reason this file exists.
//
// A process on the gateway host that opens a socket egresses through nftables'
// **output** chain. A packet that arrives on a bridge from somewhere else — a
// Docker container's veth, a containerd bridge, a Kubernetes Pod — is *forwarded*
// and goes through **prerouting/forward** instead. `auto_redirect` exists for the
// second case (sing-tun builds its prerouting NAT chain and REDIRECTs those
// packets into the tunnel; see sing-tun redirect_nftables.go). The existing TUN
// assertion in linux_service_docker_test.go curls from the container itself, so
// it only ever exercised the output chain — meaning "Linux TUN captures
// Docker/containerd bridge egress", which CLAUDE.md states as a feature and which
// the whole K8s DaemonSet story rests on, had no test at all.
//
// The topology below reproduces the forwarded path without nesting a container
// runtime: a bridge plus a veth into a network namespace is the same kernel path
// docker0 and a CNI bridge use.
//
//	tp-e2e-tun (privileged, systemd as pid 1)
//	 ├─ trust-proxy install --mode tun     (auto_redirect on by default)
//	 ├─ br-tp 10.88.0.1/24                 ← stands in for docker0 / cni0
//	 ├─ netns "app":    10.88.0.2, default via 10.88.0.1        ← the "container"
//	 └─ netns "origin": uplink 10.99.0.2, serves 203.0.113.10   ← "the internet"
//	    (the gateway's default route points at it)
//
// The origin's address is deliberately not covered by ANY prefix on the gateway's
// interfaces, and getting that right is most of the reason this topology looks
// the way it does. sing-tun feeds every interface *prefix* into
// inet4_local_address_set (redirect_nftables.go, nftablesCreateLocalAddressSets)
// and the prerouting chain returns early for destinations in it. So it is not
// enough to keep the origin off the gateway's `lo`: putting the origin's /24 on
// the gateway's own veth would declare that whole /24 local, forwarded packets
// would skip the redirect chain entirely, and every assertion below would pass
// with the tunnel doing nothing. (It did, on the first run of this suite.)
//
// That pulls against a second constraint. Once a connection *is* permitted, the
// gateway dials the origin itself, and under TUN `auto_detect_interface` binds
// that socket to the default interface (route/network.go: ByAddr first, default
// interface otherwise) — a more specific `via` route through some other veth is
// unusable from a socket bound elsewhere. The way to satisfy both is to make the
// origin namespace the gateway's *uplink*: an ordinary 10.99.0.0/24 point-to-
// point link carries the default route, and the service answers on a 203.0.113.10
// that lives on the origin's own loopback. Not local to the gateway, yet reachable
// from a socket bound to the default interface.
//
// 203.0.113.10 is TEST-NET-3 rather than RFC1918 for the reason the dataplane
// suite documents: private CIDRs join the permit set whenever the gate is open,
// so a private origin would be reachable no matter what the policy said.
//
// Run with: make e2e-tun   (needs docker; skipped otherwise)
package test

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// bridgeIP is the gateway's address on the stand-in container bridge. It is a
	// local address, so it is excluded from redirection by design — which makes it
	// the right probe for "the LAN still works".
	bridgeIP = "10.88.0.1"
	// appIP is the "container": everything it sends is forwarded, never local.
	appIP = "10.88.0.2"
	// tunOriginIP answers on the origin namespace's own loopback, so it is covered
	// by no prefix on any gateway interface: not local, not private, and therefore
	// subject to both the redirect chain and the Permit gate.
	tunOriginIP = "203.0.113.10"
	// uplinkGW / uplinkNS are the two ends of the point-to-point link that carries
	// the gateway's default route. Ordinary transit addresses; nothing is served on
	// them.
	uplinkGW = "10.99.0.1"
	uplinkNS = "10.99.0.2"
)

type tunLab struct{ *systemdBox }

// newTunLab builds the topology *before* installing, so the interfaces exist when
// sing-tun snapshots local addresses and initialises its nftables table.
func newTunLab(t *testing.T, name string) *tunLab {
	t.Helper()
	requireDocker(t)
	c := &systemdBox{t: t, name: name, image: buildSystemdImage(t), binary: buildLinuxBinary(t)}
	c.boot()
	l := &tunLab{c}

	l.exec("sysctl -w net.ipv4.ip_forward=1")
	// Return traffic for a redirected connection comes back through the bridge; a
	// strict reverse-path check would drop it and look exactly like "capture is
	// broken". Debian's default is already loose, but this suite must not depend
	// on the base image's sysctl defaults staying that way.
	l.exec("sysctl -w net.ipv4.conf.all.rp_filter=0 || true")

	// The stand-in container bridge and its namespace.
	l.exec("ip link add br-tp type bridge")
	l.exec("ip addr add " + bridgeIP + "/24 dev br-tp")
	l.exec("ip link set br-tp up")
	l.exec("ip netns add app")
	l.exec("ip link add veth-app type veth peer name veth-app-c")
	l.exec("ip link set veth-app master br-tp up")
	l.exec("ip link set veth-app-c netns app")
	l.exec("ip netns exec app ip addr add " + appIP + "/24 dev veth-app-c")
	l.exec("ip netns exec app ip link set veth-app-c up")
	l.exec("ip netns exec app ip link set lo up")
	l.exec("ip netns exec app ip route add default via " + bridgeIP)

	// The origin namespace, standing in for the internet: an ordinary transit link
	// carries the gateway's default route, and the service answers on an address
	// that belongs to no gateway interface.
	l.exec("ip netns add origin")
	l.exec("ip link add veth-o type veth peer name veth-o-c")
	l.exec("ip addr add " + uplinkGW + "/24 dev veth-o")
	l.exec("ip link set veth-o up")
	l.exec("ip link set veth-o-c netns origin")
	l.exec("ip netns exec origin ip addr add " + uplinkNS + "/24 dev veth-o-c")
	l.exec("ip netns exec origin ip link set veth-o-c up")
	l.exec("ip netns exec origin ip link set lo up")
	l.exec("ip netns exec origin ip addr add " + tunOriginIP + "/32 dev lo")
	l.exec("ip netns exec origin ip route add default via " + uplinkGW)
	l.exec("ip netns exec origin sysctl -w net.ipv4.conf.all.rp_filter=0 || true")
	// The gateway's default route now points at the origin namespace. A more
	// specific route would not do: once a destination is permitted the gateway
	// dials it itself, and under TUN that socket is bound to the *default*
	// interface, which makes routes on any other link unusable.
	l.exec("ip route replace default via " + uplinkNS + " dev veth-o")
	l.exec("mkdir -p /srv/o && echo ORIGIN-OK > /srv/o/index.html")
	l.exec("cd /srv/o && setsid nohup ip netns exec origin python3 -m http.server 80 --bind " + tunOriginIP + " >/dev/null 2>&1 < /dev/null &")
	// A LAN service on the gateway itself, for the "strict_route did not kill the
	// local subnet" assertion.
	l.exec("mkdir -p /srv/l && echo LOCAL-OK > /srv/l/index.html")
	l.exec("cd /srv/l && setsid nohup python3 -m http.server 80 --bind " + bridgeIP + " >/dev/null 2>&1 < /dev/null &")

	// Before the gateway exists, both must already be reachable from the
	// namespace. Otherwise a later "blocked" result would prove nothing: it could
	// just be a topology that never worked.
	l.waitFor("origin reachable from the app namespace before the gateway exists", func() bool {
		return strings.Contains(l.fromApp(tunOriginIP), "ORIGIN-OK")
	})
	l.waitFor("gateway's own bridge address reachable from the app namespace", func() bool {
		return strings.Contains(l.fromApp(bridgeIP), "LOCAL-OK")
	})

	if out := l.exec("trust-proxy install --mode tun -y" + consoleNone); !strings.Contains(out, "mode:    tun") {
		t.Fatalf("install --mode tun failed:\n%s", out)
	}
	l.waitAPI("21585")
	if st := l.exec("trust-proxy status --json"); !strings.Contains(st, `"mode": "tun"`) {
		t.Fatalf("gateway did not come up in TUN mode: %s", st)
	}
	return l
}

// fromApp fetches a URL from inside the "container" namespace. Every packet it
// produces is forwarded by the gateway host — which is the only path this file
// is about.
func (l *tunLab) fromApp(ip string) string {
	return l.exec("ip netns exec app curl -s -m 6 http://" + ip + "/ 2>&1 || true")
}

func (l *tunLab) waitFor(what string, ok func() bool) {
	l.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(time.Second)
	}
	l.t.Fatalf("timed out waiting for: %s", what)
}

// settleApp polls until egress from the namespace matches want, absorbing the hot
// reload a policy change triggers. Polling rather than sleeping: a fixed sleep
// here would be both flaky and slow.
func (l *tunLab) settleApp(want bool) bool {
	l.t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(l.fromApp(tunOriginIP), "ORIGIN-OK") == want {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// logMark returns the current length of serve.log, so a later logSince reads only
// what one specific action produced. Grepping the whole file would happily match
// a line from three assertions ago.
func (l *tunLab) logMark() int {
	n, _ := strconv.Atoi(strings.TrimSpace(l.exec("wc -l < /var/lib/trust-proxy/serve.log 2>/dev/null || echo 0")))
	return n
}

func (l *tunLab) logSince(mark int) string {
	return l.exec("tail -n +" + strconv.Itoa(mark+1) + " /var/lib/trust-proxy/serve.log 2>/dev/null || true")
}

// nftRuleset is what the kernel actually has, as opposed to what the config asked
// for. `auto_redirect` failing to initialise is not loud.
func (l *tunLab) nftRuleset() string {
	return l.exec("nft list ruleset 2>&1 || true")
}

// The claim: traffic forwarded from a container bridge enters the tunnel through
// nftables, and every policy axis applies to it exactly as it does to the
// gateway's own traffic.
func TestLinuxTUNCapturesForwardedBridgeTraffic(t *testing.T) {
	l := newTunLab(t, "tp-e2e-tun")

	// (1) Precondition, checked rather than assumed. sing-tun builds an inet table
	// named after sing-box; without it every result below would be about plain
	// routing and would say nothing about auto_redirect.
	rules := l.nftRuleset()
	if !strings.Contains(rules, "table inet sing-box") {
		t.Fatalf("auto_redirect did not install its nftables table — nothing below would be "+
			"testing the forwarded path:\n%s", rules)
	}
	if !strings.Contains(rules, "chain prerouting") {
		t.Fatalf("no prerouting chain in the sing-box table: the output chain alone only "+
			"covers the gateway's own processes, not forwarded traffic:\n%s", rules)
	}

	// (2)+(3) A fresh install permits nothing. The forwarded connection has to be
	// *seen* (captured) and *refused* (policy applied). Capture without policy is
	// the worst intermediate state there is: it looks like the gateway is in
	// charge while nothing is being enforced.
	mark := l.logMark()
	if !l.settleApp(false) {
		t.Fatalf("a fresh install permits nothing, yet the container reached the origin:\n%s",
			l.logSince(mark))
	}
	seen := l.logSince(mark)
	if !strings.Contains(seen, tunOriginIP) {
		t.Fatalf("the forwarded connection never appeared in the gateway's log at all — it "+
			"left the machine without passing through the tunnel:\n%s", seen)
	}
	// The redirect handler logs a distinct line ("inbound redirect connection
	// from", protocol/tun/inbound.go) from the tun handler's own ("inbound
	// connection from"). That is the difference between the nftables path and
	// plain auto_route, so it is what gets asserted rather than a generic
	// "inbound/tun".
	if !strings.Contains(seen, "inbound redirect connection from "+appIP) {
		t.Fatalf("the container's traffic did not arrive through the nftables redirect "+
			"(want `inbound redirect connection from %s`):\n%s", appIP, seen)
	}
	if !strings.Contains(seen, "blocked") {
		t.Fatalf("the forwarded connection was captured but default-deny did not refuse it — "+
			"captured-but-unenforced is worse than uncaptured:\n%s", seen)
	}

	// (4) The point of the whole feature: permit the destination and the container
	// egresses through the gateway with no change to the container.
	l.exec("trust-proxy acl add permit " + tunOriginIP + " --type ip")
	if !l.settleApp(true) {
		t.Fatalf("after permitting %s the container still cannot reach it:\n%s",
			tunOriginIP, l.logSince(l.logMark()-40))
	}

	// (5) Permit and Route stay orthogonal on the forwarded path too. no-proxy
	// says *where* permitted traffic goes; it must never decide *whether* it goes.
	l.exec("trust-proxy acl rm permit " + tunOriginIP + " --type ip")
	if !l.settleApp(false) {
		t.Fatal("removing the permit did not close the gate for forwarded traffic")
	}
	l.exec("trust-proxy acl add no-proxy " + tunOriginIP + " --type ip")
	if !l.settleApp(false) {
		t.Fatal("no-proxy opened the Permit gate for forwarded traffic — the two axes are " +
			"supposed to be orthogonal")
	}
	l.exec("trust-proxy acl rm no-proxy " + tunOriginIP + " --type ip")

	// (6) The local subnet has to keep working. strict_route plus a redirect chain
	// severing the LAN is the classic way this feature bricks a node, and it shows
	// up in none of the egress assertions above — on a K8s node it would mean
	// kubelet, CNI and DNS all losing the Pod network at once.
	l.waitFor("the container can still reach the gateway's own bridge address", func() bool {
		return strings.Contains(l.fromApp(bridgeIP), "LOCAL-OK")
	})

	// (7) The teeth. Everything above would stay green if plain auto_route
	// happened to catch forwarded packets on its own and auto_redirect were doing
	// nothing. Turn it off: the nftables table must go, and forwarded traffic must
	// stop arriving through the redirect handler.
	l.exec("trust-proxy tun set --auto-redirect=false")
	l.waitFor("the nftables table to go away once auto_redirect is off", func() bool {
		return !strings.Contains(l.nftRuleset(), "table inet sing-box")
	})
	mark = l.logMark()
	l.fromApp(tunOriginIP)
	time.Sleep(2 * time.Second)
	if after := l.logSince(mark); strings.Contains(after, "inbound redirect connection") {
		t.Fatalf("auto_redirect is off but traffic still arrives through the redirect handler — "+
			"assertion (2) above was not testing what it claims:\n%s", after)
	}
}

// What happens on a node that has no nftables — the question the DaemonSet's
// preflight initContainer is supposed to answer before it lets a Pod start.
//
// Two things are being pinned down here, and they are pinned down by running the
// thing rather than by reading it, because both have a plausible wrong answer
// that reads fine:
//
//   - Does the gateway fail loudly, or does it start and quietly forward
//     nothing? A gateway that reports healthy while every Pod on the node
//     egresses straight past it is the worst outcome in this whole feature, and
//     it is the outcome the preflight container exists to prevent.
//   - Is `nft` (the userspace binary) actually required? sing-tun talks to
//     nftables over netlink (sagernet/nftables -> mdlayher/netlink) and never
//     execs `nft`, but internal/doctor reports usable=false without that binary
//     in PATH — and deploy/kubernetes/daemonset.yaml gates on exactly that
//     field. If the binary is not required, that preflight refuses nodes which
//     would have worked.
//
// Removing the *kernel* side inside a privileged container is not something this
// suite can do (it shares the host's netfilter). So the two halves are separated:
// this test removes the binary, which is what a slim node image actually looks
// like, and asserts what each layer then says.
func TestLinuxTUNWithoutNftBinary(t *testing.T) {
	l := newTunLab(t, "tp-e2e-tun-nonft")

	// Baseline: with `nft` present the doctor says usable, which is what the
	// DaemonSet preflight greps for. Without this the assertion below could pass
	// on a container where the doctor never worked in the first place.
	if before := l.exec("trust-proxy doctor nftables --json"); !strings.Contains(before, `"usable": true`) {
		t.Fatalf("doctor does not report nftables usable even with nft installed; "+
			"nothing below would mean anything:\n%s", before)
	}

	// dpkg rather than apt-get remove: apt would also take the systemd units and
	// dependencies with it. Only the userspace binary goes away; the kernel's
	// netfilter tables stay exactly as they were, which is the point.
	l.exec("dpkg --remove --force-depends nftables >/dev/null 2>&1 || apt-get remove -y nftables >/dev/null 2>&1 || true")
	if out := l.exec("command -v nft || echo GONE"); !strings.Contains(out, "GONE") {
		t.Skipf("could not remove the nft binary from this image, so there is nothing to observe: %s", out)
	}

	rep := l.exec("trust-proxy doctor nftables --json")
	t.Logf("doctor with no nft binary:\n%s", rep)

	// Restart so auto_redirect re-initialises with the binary absent.
	l.exec("systemctl restart trust-proxy")
	l.waitAPI("21585")

	// The observation that decides whether deploy/ needs changing: can forwarded
	// traffic still be captured and refused without the userspace binary?
	mark := l.logMark()
	blocked := l.settleApp(false)
	seen := l.logSince(mark)
	redirected := strings.Contains(seen, "inbound redirect connection from "+appIP)
	t.Logf("without the nft binary: default-deny held=%v, arrived via redirect=%v", blocked, redirected)

	// Whatever the answer, this must hold: the gateway may not be *silently*
	// permissive. Either it still captures and refuses, or it fails visibly. A
	// container reaching the origin under a fresh install's default-deny means
	// traffic bypassed the gateway entirely.
	if !blocked {
		t.Fatalf("without nftables the container reached the origin under default-deny — "+
			"traffic is bypassing the gateway silently, which is exactly what the "+
			"preflight check is supposed to make impossible:\n%s\n--- doctor ---\n%s",
			seen, rep)
	}

	// And the finding that matters for the DaemonSet: if capture still works with
	// no `nft` binary, then gating the preflight on doctor's usable=false rejects
	// nodes that would have been fine.
	if redirected && strings.Contains(rep, `"usable": false`) {
		t.Logf("FINDING: forwarded traffic is still captured through the redirect chain " +
			"with no nft binary present, yet doctor reports usable=false. sing-tun uses " +
			"netlink, not the CLI. deploy/kubernetes/daemonset.yaml and the Helm chart " +
			"gate their preflight on that field and would refuse such a node.")
	}
}
