// Package netwatch observes the host's own routing and interface state.
//
// Two attack classes bypass a routing-based gateway without ever touching its
// data plane, so the gateway cannot see them in its connection log — it has to
// look at the machine instead:
//
//   - TunnelVision (CVE-2024-3661): a rogue DHCP server hands out classless
//     static routes (option 121) that are more specific than the tunnel's split
//     defaults, so traffic leaves in the clear and the gateway never sees it.
//   - TunnelCrack "LocalNet": a hostile network claims that public destinations
//     are on the local subnet, and the "LAN is always direct" exception — which
//     this gateway has, in gateway.privateCIDRs — sends them outside the tunnel
//     AND around the Permit gate.
//
// This package only reads. It reports; enforcing (a firewall kill switch,
// narrowing the LAN bypass) is a separate decision with a very different failure
// mode: a bug here produces a spurious alert, a bug there takes the machine off
// the network.
package netwatch

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Route is one entry of the host routing table, reduced to what matters here.
type Route struct {
	Prefix    netip.Prefix `json:"prefix"`
	Interface string       `json:"interface"`
	Gateway   string       `json:"gateway,omitempty"`
}

// Snapshot is the observed network state at one moment.
type Snapshot struct {
	Taken time.Time `json:"taken"`
	// HostRoutes counts /32 and /128 entries: normal on this design (one per
	// direct dial), surfaced so their volume is visible without alerting.
	HostRoutes int      `json:"host_routes"`
	Routes     []Route  `json:"routes"`
	LocalNets  []string `json:"local_nets"`  // real on-link prefixes of up interfaces
	TunIfaces  []string `json:"tun_ifaces"`  // interfaces carrying our tunnel routes
	DefaultVia string   `json:"default_via"` // interface of the IPv4 default route
}

// Finding is a deviation worth reporting.
type Finding struct {
	Kind    string `json:"kind"`   // route-hijack | tunnel-route-missing
	Detail  string `json:"detail"` // human-readable, names the route
	Route   Route  `json:"route"`
	Sighted string `json:"sighted"` // RFC3339
}

// Watcher polls the routing table and reports deviations from the baseline it
// captured when the tunnel came up.
type Watcher struct {
	mu         sync.Mutex
	baseline   map[string]Route // prefix|iface -> route, as of the last Rebaseline
	last       Snapshot
	onFind     func(Finding)
	tunOnly    bool           // only meaningful while the tunnel is up
	tunAddrs   []netip.Prefix // our tun's own addresses, used to identify our interface
	dialed     func(string) bool
	hostRoutes bool // report /32 and /128 routes too (noisy by design, see Poll)
	stop       chan struct{}
}

// New builds a watcher. onFinding may be nil.
func New(onFinding func(Finding)) *Watcher {
	return &Watcher{onFind: onFinding, stop: make(chan struct{})}
}

// Start polls every interval until Stop. Interval <= 0 disables polling (the
// watcher still answers Snapshot()).
func (w *Watcher) Start(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-w.stop:
				return
			case <-t.C:
				w.Poll()
			}
		}
	}()
}

// Stop ends polling.
func (w *Watcher) Stop() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
}

// SetTunnelActive tells the watcher whether a tunnel is expected, and which
// addresses identify ours. Route-hijack findings only make sense while one is
// up: without a tunnel, "traffic goes out via the physical interface" is simply
// how the machine works. Identifying our own interface by address matters on a
// box that also runs Tailscale or another VPN — "some utun exists" is not the
// same as "our tunnel is still carrying traffic".
func (w *Watcher) SetTunnelActive(active bool, tunAddrs []netip.Prefix) {
	w.mu.Lock()
	w.tunOnly = active
	w.tunAddrs = tunAddrs
	w.mu.Unlock()
	if active {
		w.Rebaseline()
	}
}

// SetDialedCheck registers "have we ourselves connected to this address", used
// to filter host routes when reporting them is enabled.
//
// It is not reliable enough to enable them by default: under TUN the sniffed
// domain replaces the destination, so the address never reaches the connection
// tracker, and the resolver's own dials don't pass through it at all. Measured
// on a real box, every ordinary direct connection produced a /32 route via the
// physical interface — reporting those would bury the signal exactly the way the
// beacon cooldown once did.
func (w *Watcher) SetDialedCheck(fn func(string) bool) {
	w.mu.Lock()
	w.dialed = fn
	w.mu.Unlock()
}

// SetReportHostRoutes includes /32 and /128 routes in hijack findings. Off by
// default: on this design the data plane creates them constantly. The classic
// DHCP option-121 hijack covers ranges (0.0.0.0/1, 128.0.0.0/1, a /24), which is
// always reported; a host-route variant that steals one destination is the case
// this switch buys, at the cost of a finding per direct connection.
func (w *Watcher) SetReportHostRoutes(v bool) {
	w.mu.Lock()
	w.hostRoutes = v
	w.mu.Unlock()
}

// Rebaseline records the current table as expected. Called after the data plane
// (re)starts, so routes the gateway itself installs are not reported.
func (w *Watcher) Rebaseline() {
	snap, err := w.observe()
	if err != nil {
		return
	}
	base := make(map[string]Route, len(snap.Routes))
	for _, r := range snap.Routes {
		base[routeKey(r)] = r
	}
	w.mu.Lock()
	w.baseline = base
	w.last = snap
	w.mu.Unlock()
}

// Snapshot returns the most recent observation (polling one if none yet).
func (w *Watcher) Snapshot() Snapshot {
	w.mu.Lock()
	last := w.last
	w.mu.Unlock()
	if last.Taken.IsZero() {
		if snap, err := w.observe(); err == nil {
			w.mu.Lock()
			w.last = snap
			w.mu.Unlock()
			return snap
		}
	}
	return last
}

// Poll observes once and reports new routes that could carry traffic around the
// tunnel. Returns the findings it reported.
func (w *Watcher) Poll() []Finding {
	snap, err := w.observe()
	if err != nil {
		return nil
	}
	w.mu.Lock()
	active, baseline, dialed, wantHost := w.tunOnly, w.baseline, w.dialed, w.hostRoutes
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
			// The data plane installs one of these per direct dial; only report
			// them when asked, and even then not for addresses we know we dialled.
			if !wantHost || (dialed != nil && dialed(r.Prefix.Addr().String())) {
				continue
			}
		}
		f := Finding{
			Kind: "route-hijack",
			Detail: fmt.Sprintf(
				"new route %s via %s appeared after the tunnel came up — traffic to it leaves outside the tunnel (TunnelVision / DHCP option 121 shape)",
				r.Prefix, r.Interface),
			Route: r, Sighted: snap.Taken.Format(time.RFC3339),
		}
		out = append(out, f)
	}
	if len(snap.TunIfaces) == 0 {
		out = append(out, Finding{
			Kind:    "tunnel-route-missing",
			Detail:  "no tunnel routes present while the gateway is in tun mode — traffic is not being captured",
			Sighted: snap.Taken.Format(time.RFC3339),
		})
	}
	// Findings become the new baseline: report a hijack once, not every poll.
	if len(out) > 0 {
		w.Rebaseline()
		if w.onFind != nil {
			for _, f := range out {
				w.onFind(f)
			}
		}
	}
	return out
}

// IsLocal reports whether addr belongs to a prefix that is genuinely on-link for
// one of this host's interfaces. The gateway's "LAN is always direct" exception
// covers all of RFC1918 + CGNAT; a hostile network only has to claim one of
// those ranges to pull traffic out of the tunnel and around the Permit gate
// (TunnelCrack LocalNet), so "private" and "actually local" must be told apart.
func (w *Watcher) IsLocal(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, s := range w.Snapshot().LocalNets {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

// observe takes a snapshot and narrows TunIfaces to the interface(s) holding our
// own tunnel addresses, when we know them.
func (w *Watcher) observe() (Snapshot, error) {
	snap, err := Observe()
	if err != nil {
		return snap, err
	}
	w.mu.Lock()
	want := w.tunAddrs
	w.mu.Unlock()
	if len(want) == 0 {
		return snap, nil
	}
	ours := ifacesHolding(want)
	if len(ours) == 0 {
		snap.TunIfaces = nil
		return snap, nil
	}
	var kept []string
	for _, name := range snap.TunIfaces {
		if ours[name] {
			kept = append(kept, name)
		}
	}
	snap.TunIfaces = kept
	return snap, nil
}

// ifacesHolding returns the interfaces configured with any of the given
// addresses (our tun's own addresses identify it unambiguously).
func ifacesHolding(prefixes []netip.Prefix) map[string]bool {
	out := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			for _, p := range prefixes {
				if p.Contains(addr) {
					out[ifi.Name] = true
				}
			}
		}
	}
	return out
}

// isHostRoute reports whether the prefix covers exactly one address.
func isHostRoute(p netip.Prefix) bool { return p.Bits() == p.Addr().BitLen() }

// routeKey identifies a route for baseline comparison.
func routeKey(r Route) string { return r.Prefix.String() + "|" + r.Interface }

// carriesPublicTraffic reports whether a prefix can route public destinations.
// Link-local, multicast and loopback cannot; the RFC1918 ranges are excluded
// because a LAN route to them is ordinary — the LocalNet check covers that side.
func carriesPublicTraffic(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	a := p.Addr()
	switch {
	case a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsMulticast():
		return false
	case a.IsPrivate():
		return false
	}
	// A /32 (or /128) host route to a public address is exactly how a DHCP-based
	// hijack pins one destination outside the tunnel, so those count.
	return true
}

// localPrefixes lists the on-link prefixes of every up, non-loopback interface.
func localPrefixes() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			p, err := netip.ParsePrefix(ipnet.String())
			if err != nil {
				continue
			}
			out = append(out, p.Masked().String())
		}
	}
	sort.Strings(out)
	return dedupe(out), nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// isTunnelIface reports whether an interface name looks like a tunnel device.
func isTunnelIface(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "utun") || strings.HasPrefix(n, "tun") || strings.HasPrefix(n, "wg")
}
