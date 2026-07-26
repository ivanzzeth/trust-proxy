package netwatch

import (
	"net/netip"
	"testing"
	"time"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// pollWith runs the finding logic against a fabricated table, so the assertions
// don't depend on the machine the test happens to run on.
func (w *Watcher) pollTable(snap Snapshot) []Finding {
	w.mu.Lock()
	active, baseline, dialed := w.tunOnly, w.baseline, w.dialed
	w.last = snap
	w.mu.Unlock()
	if !active || baseline == nil {
		return nil
	}
	tun := map[string]bool{}
	for _, i := range snap.TunIfaces {
		tun[i] = true
	}
	var out []Finding
	for _, r := range snap.Routes {
		if _, known := baseline[routeKey(r)]; known {
			continue
		}
		if tun[r.Interface] || !carriesPublicTraffic(r.Prefix) {
			continue
		}
		if isHostRoute(r.Prefix) {
			if !w.hostRoutes || (dialed != nil && dialed(r.Prefix.Addr().String())) {
				continue
			}
		}
		out = append(out, Finding{Kind: "route-hijack", Route: r})
	}
	return out
}

func (w *Watcher) setBaseline(routes []Route) {
	base := map[string]Route{}
	for _, r := range routes {
		base[routeKey(r)] = r
	}
	w.mu.Lock()
	w.baseline = base
	w.mu.Unlock()
}

// The TunnelVision shape: after the tunnel is up, a route appears via the
// physical interface covering public space. That traffic never reaches the
// gateway, so nothing in the connection log would ever show it.
func TestNewNonTunnelRouteToPublicSpaceIsReported(t *testing.T) {
	w := New(nil)
	w.tunOnly = true
	base := []Route{{Prefix: mustPrefix(t, "0.0.0.0/1"), Interface: "utun4"}}
	w.setBaseline(base)

	snap := Snapshot{
		Taken:     time.Now(),
		TunIfaces: []string{"utun4"},
		Routes: append(base,
			Route{Prefix: mustPrefix(t, "203.0.113.0/24"), Interface: "en0", Gateway: "192.168.64.1"},
		),
	}
	found := w.pollTable(snap)
	if len(found) != 1 || found[0].Route.Prefix.String() != "203.0.113.0/24" {
		t.Fatalf("findings = %+v, want the injected route", found)
	}
}

// Host routes are off by default (one per direct dial would bury the signal —
// measured on a real box). With them enabled, addresses we dialled ourselves are
// still filtered out.
func TestOwnEscapeRoutesAreNotHijacks(t *testing.T) {
	w := New(nil)
	w.tunOnly = true
	w.setBaseline(nil)
	w.SetDialedCheck(func(ip string) bool { return ip == "223.5.5.5" })
	w.SetReportHostRoutes(true) // off by default; this test is about the filter

	snap := Snapshot{
		Taken:     time.Now(),
		TunIfaces: []string{"utun4"},
		Routes: []Route{
			{Prefix: mustPrefix(t, "223.5.5.5/32"), Interface: "en0"},    // ours: we dialled it
			{Prefix: mustPrefix(t, "198.51.100.7/32"), Interface: "en0"}, // not ours
		},
	}
	found := w.pollTable(snap)
	if len(found) != 1 || found[0].Route.Prefix.Addr().String() != "198.51.100.7" {
		t.Fatalf("findings = %+v, want only the address we never dialled", found)
	}
}

// By default a /32 via the physical interface is not a finding at all.
func TestHostRoutesAreNotReportedByDefault(t *testing.T) {
	w := New(nil)
	w.tunOnly = true
	w.setBaseline(nil)
	snap := Snapshot{
		Taken: time.Now(), TunIfaces: []string{"utun4"},
		Routes: []Route{{Prefix: mustPrefix(t, "198.51.100.7/32"), Interface: "en0"}},
	}
	if found := w.pollTable(snap); len(found) != 0 {
		t.Fatalf("findings = %+v, want none with host routes off", found)
	}
}

// LAN and link-local routes are how a machine works; only public-carrying
// prefixes can steal tunnelled traffic.
func TestOrdinaryLocalRoutesAreIgnored(t *testing.T) {
	w := New(nil)
	w.tunOnly = true
	w.setBaseline(nil)
	snap := Snapshot{
		Taken:     time.Now(),
		TunIfaces: []string{"utun4"},
		Routes: []Route{
			{Prefix: mustPrefix(t, "192.168.31.0/24"), Interface: "en0"},
			{Prefix: mustPrefix(t, "169.254.0.0/16"), Interface: "en0"},
			{Prefix: mustPrefix(t, "224.0.0.0/4"), Interface: "en0"},
		},
	}
	if found := w.pollTable(snap); len(found) != 0 {
		t.Fatalf("findings = %+v, want none", found)
	}
}

// IsLocal is what separates "really on-link" from "inside the LAN bypass".
func TestIsLocalOnlyAcceptsRealSubnets(t *testing.T) {
	w := New(nil)
	w.mu.Lock()
	w.last = Snapshot{Taken: time.Now(), LocalNets: []string{"192.168.31.0/24"}}
	w.mu.Unlock()

	if !w.IsLocal(netip.MustParseAddr("192.168.31.7")) {
		t.Fatal("an address on the real subnet must be local")
	}
	if w.IsLocal(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("a private address outside every local subnet must not count as local")
	}
	if w.IsLocal(netip.MustParseAddr("100.64.7.9")) {
		t.Fatal("CGNAT space is inside the LAN bypass but is not on-link here")
	}
}
