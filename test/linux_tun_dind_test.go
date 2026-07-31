//go:build docker_e2e

// The DOCKER-USER layer: what a real dockerd does to the redirect chain, and
// what sing-tun does back.
//
// The sibling suite (linux_tun_docker_test.go) reproduces the forwarded path
// with a bridge and a veth into a network namespace, which is the same kernel
// path docker0 uses and is enough to prove auto_redirect captures forwarded
// traffic. What it can never reproduce is Docker's own firewall: when dockerd
// starts it creates `table ip filter` with a `DOCKER-USER` chain and jumps
// forwarded container traffic through it. Rules in that chain run *before*
// Docker's own accept rules, and a plain install of them drops the traffic
// auto_redirect just redirected — a container that reaches nothing at all,
// with the gateway insisting it captured everything.
//
// sing-tun handles this in redirect_nftables_docker.go: it inserts two accept
// rules into DOCKER-USER matching its tun interface (iifname and oifname), tags
// them with a comment prefixed "!<table>: Docker compatibility ", and keeps an
// nftables *monitor* running so that a `docker network` command — which
// rewrites that chain — gets them reconciled back in. That whole file has no
// coverage anywhere, and it cannot get any without a real dockerd: the chain it
// reconciles against does not exist otherwise.
//
// This is nested containerisation, so it is slower and more fragile than the
// rest of the suite and is gated behind TP_E2E_DIND=1 rather than run on every
// PR. CI runs it nightly and on workflow_dispatch.
//
// Ordering matters more here than anywhere else in these tests, and each step
// is ordered for a reason spelled out at the call site: dockerd must be running
// (so docker0 and the filter table exist) before the gateway installs, the
// busybox image must be pulled before the default route is aimed at a namespace
// with no internet, and the gateway must install last so sing-tun snapshots
// local addresses with every interface already present.
//
// Run with: TP_E2E_DIND=1 make e2e-tun-dind
package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildDindImage extends the systemd image with a real docker daemon. Separate
// from buildSystemdImage because every other suite would pay the download for a
// daemon it never starts.
func buildDindImage(t *testing.T) string {
	t.Helper()
	const tag = "trust-proxy-dind-test"
	dir := t.TempDir()
	// docker.io from Debian rather than the upstream convenience script: it comes
	// with a systemd unit, which is the point of running systemd as pid 1 here.
	// iptables is pulled in as a dependency and defaults to the nft backend on
	// bookworm, which is what makes dockerd create `table ip filter` with a
	// DOCKER-USER chain that sing-tun can find.
	//
	// ca-certificates is listed explicitly and is not optional: with
	// --no-install-recommends nothing here pulls it in, and without a CA bundle
	// the nested daemon cannot verify registry-1.docker.io, so every pull dies
	// with "x509: certificate signed by unknown authority". That is how this
	// test's first CI run finished in 62 seconds and reported success.
	dockerfile := `FROM debian:12
RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        systemd systemd-sysv dbus ca-certificates curl iproute2 procps python3 nftables \
        docker.io && \
    rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "build", "-q", "-t", tag, dir).CombinedOutput()
	if err != nil {
		t.Skipf("cannot build the docker-in-docker test image: %v\n%s", err, out)
	}
	return tag
}

// The claim: a container started by a real dockerd is captured by auto_redirect,
// is subject to the Permit gate like anything else, and keeps working after
// Docker rewrites its own firewall chain.
func TestLinuxTUNCapturesRealDockerBridge(t *testing.T) {
	if os.Getenv("TP_E2E_DIND") != "1" {
		t.Skip("nested docker is slow and fragile; set TP_E2E_DIND=1 to run it")
	}
	requireDocker(t)

	c := &systemdBox{t: t, name: "tp-e2e-tun-dind", image: buildDindImage(t), binary: buildLinuxBinary(t)}
	c.boot()
	l := &tunLab{c}

	l.exec("sysctl -w net.ipv4.ip_forward=1")
	l.exec("sysctl -w net.ipv4.conf.all.rp_filter=0 || true")

	// (1) dockerd first. It must be up before anything else, for two separate
	// reasons: docker0 has to exist when sing-tun snapshots local addresses, and
	// `table ip filter` / DOCKER-USER only exists once dockerd has configured its
	// firewall. Starting it after the gateway would test a different, easier
	// problem — sing-tun reconciling a chain it already knew about.
	l.exec("systemctl start docker || true")
	l.waitFor("dockerd inside the container to accept commands", func() bool {
		return strings.Contains(l.exec("docker info >/dev/null 2>&1 && echo UP || echo DOWN"), "UP")
	})

	// (2) Pull now, while the container still has its original default route.
	// After step (4) the only "internet" is a namespace serving one static file,
	// and an image pull at that point would fail for reasons having nothing to do
	// with what is under test.
	//
	// A failed pull is fatal, not a skip. Every assertion below needs a container,
	// so skipping here leaves a job whose entire purpose is this one test
	// reporting success having tested nothing — which is exactly what happened
	// the first time it ran in CI.
	if out := l.exec("docker pull -q busybox:latest 2>&1 || echo PULLFAIL"); strings.Contains(out, "PULLFAIL") {
		t.Fatalf("cannot pull busybox inside the nested daemon, so there is no container to "+
			"forward and nothing below this line means anything: %s", out)
	}

	// (3) DOCKER-USER must exist before the gateway starts, or this test silently
	// degrades into the netns one.
	if chain := l.exec("nft list chain ip filter DOCKER-USER 2>&1 || true"); !strings.Contains(chain, "DOCKER-USER") {
		t.Skipf("dockerd did not create an nftables DOCKER-USER chain here (iptables-legacy "+
			"backend?), so sing-tun's compatibility rules have nothing to attach to:\n%s", chain)
	}

	// (4) The origin namespace and the default route pointed at it, exactly as in
	// the netns suite and for the same reasons: an address on no gateway interface
	// (so the redirect chain applies), reached over the default interface (so the
	// gateway can dial it once permitted), outside RFC1918 (so the permit gate
	// governs it).
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
	l.exec("ip route replace default via " + uplinkNS + " dev veth-o")
	l.exec("mkdir -p /srv/o && echo ORIGIN-OK > /srv/o/index.html")
	l.exec("cd /srv/o && setsid nohup ip netns exec origin python3 -m http.server 80 --bind " + tunOriginIP + " >/dev/null 2>&1 < /dev/null &")

	// (5) Reachable from a real container before the gateway exists. Without this
	// the "blocked" result below could just be a topology that never worked — the
	// single most likely way this whole file passes while proving nothing.
	l.waitFor("origin reachable from a docker container before the gateway exists", func() bool {
		return strings.Contains(fromDocker(l), "ORIGIN-OK")
	})

	// (6) Install last, so every interface docker created is present when sing-tun
	// snapshots them.
	if out := l.exec("trust-proxy install --mode tun -y" + consoleNone); !strings.Contains(out, "mode:    tun") {
		t.Fatalf("install --mode tun failed:\n%s", out)
	}
	l.waitAPI("21585")

	// (7) sing-tun's Docker compatibility rules. This is the assertion that only a
	// real dockerd can produce, and the reason redirect_nftables_docker.go exists:
	// without these two accept rules, DOCKER-USER drops the traffic auto_redirect
	// just redirected, and a container reaches nothing while the gateway reports
	// it captured everything.
	l.waitFor("sing-tun to insert its compatibility rules into DOCKER-USER", func() bool {
		return strings.Contains(dockerUserChain(l), "Docker compatibility")
	})
	chain := dockerUserChain(l)
	for _, want := range []string{"iifname", "oifname"} {
		if !strings.Contains(chain, want) {
			t.Errorf("DOCKER-USER has no %s rule from sing-tun; only one direction of "+
				"redirected traffic is accepted:\n%s", want, chain)
		}
	}

	// (8) A fresh install permits nothing, and that has to hold for a container
	// too. Capture without policy is the worst state available: it looks governed.
	if !settleDocker(l, false) {
		t.Fatalf("a docker container reached the origin under a fresh install's default "+
			"deny:\n%s", l.exec("tail -50 /var/lib/trust-proxy/serve.log || true"))
	}
	seen := l.exec("tail -200 /var/lib/trust-proxy/serve.log || true")
	if !strings.Contains(seen, "inbound redirect connection from ") {
		t.Errorf("the container's traffic never arrived through the redirect chain, so it "+
			"was refused by something other than the gateway — routing, or Docker's own "+
			"firewall:\n%s", seen)
	}

	// (9) Permit opens it. This is the whole feature in one line: an unmodified
	// container, no proxy env vars, egressing through the node's gateway.
	l.exec("trust-proxy acl add permit " + tunOriginIP + " --type ip")
	if !settleDocker(l, true) {
		t.Fatalf("permitting the origin did not let the container through:\n%s",
			l.exec("tail -80 /var/lib/trust-proxy/serve.log || true"))
	}

	// (10) The monitor. `docker network create` rewrites DOCKER-USER, which is
	// precisely what startDockerFirewallMonitor watches for; without reconciliation
	// the compatibility rules are gone and every container on the node loses egress
	// at an unrelated moment, long after anyone would connect it to the gateway.
	l.exec("docker network create tp-probe-net >/dev/null 2>&1 || true")
	t.Cleanup(func() { l.exec("docker network rm tp-probe-net >/dev/null 2>&1 || true") })
	l.waitFor("compatibility rules to survive a docker network change", func() bool {
		return strings.Contains(dockerUserChain(l), "Docker compatibility")
	})
	if !settleDocker(l, true) {
		t.Fatalf("the container lost egress after `docker network create` rewrote "+
			"DOCKER-USER; sing-tun's reconciliation did not restore its rules:\n%s",
			dockerUserChain(l))
	}
}

// fromDocker fetches the origin from inside a real container on docker0. Every
// packet it sends is forwarded by the host, through DOCKER-USER, and — if
// auto_redirect is doing its job — into the tunnel.
func fromDocker(l *tunLab) string {
	return l.exec("docker run --rm busybox:latest wget -q -T 6 -O - http://" +
		tunOriginIP + "/ 2>&1 || true")
}

func dockerUserChain(l *tunLab) string {
	return l.exec("nft list chain ip filter DOCKER-USER 2>&1 || true")
}

// settleDocker polls until container egress matches want. Each attempt starts a
// container, so the interval is longer than the netns equivalent's.
func settleDocker(l *tunLab, want bool) bool {
	l.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(fromDocker(l), "ORIGIN-OK") == want {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}
