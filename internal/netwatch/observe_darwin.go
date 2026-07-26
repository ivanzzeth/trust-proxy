//go:build darwin

package netwatch

import (
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/net/route"
)

// Observe reads the kernel routing table over a route socket. No shelling out to
// netstat: this runs every poll, and parsing another program's output is how a
// monitor starts lying when the format shifts.
func Observe() (Snapshot, error) {
	snap := Snapshot{Taken: time.Now()}
	locals, err := localPrefixes()
	if err == nil {
		snap.LocalNets = locals
	}

	rib, err := route.FetchRIB(0, route.RIBTypeRoute, 0)
	if err != nil {
		return snap, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return snap, err
	}
	names := ifaceNames()
	tun := map[string]bool{}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) == 0 {
			continue
		}
		if len(rm.Addrs) <= syscall.RTAX_DST {
			continue
		}
		dst, ok := addrOf(rm.Addrs[syscall.RTAX_DST])
		if !ok {
			continue
		}
		bits := dst.BitLen()
		if len(rm.Addrs) > syscall.RTAX_NETMASK {
			if mask, ok := addrOf(rm.Addrs[syscall.RTAX_NETMASK]); ok {
				bits = maskBits(mask)
			}
		}
		prefix, err := dst.Prefix(bits)
		if err != nil {
			continue
		}
		r := Route{Prefix: prefix, Interface: names[rm.Index]}
		if len(rm.Addrs) > syscall.RTAX_GATEWAY {
			if gw, ok := addrOf(rm.Addrs[syscall.RTAX_GATEWAY]); ok {
				r.Gateway = gw.String()
			}
		}
		snap.Routes = append(snap.Routes, r)
		if prefix.Bits() == prefix.Addr().BitLen() {
			snap.HostRoutes++
		}
		if isTunnelIface(r.Interface) && carriesPublicTraffic(prefix) {
			tun[r.Interface] = true
		}
		if prefix.Bits() == 0 && prefix.Addr().Is4() && snap.DefaultVia == "" && !isTunnelIface(r.Interface) {
			snap.DefaultVia = r.Interface
		}
	}
	for name := range tun {
		snap.TunIfaces = append(snap.TunIfaces, name)
	}
	return snap, nil
}

// addrOf converts a route address to netip form, ignoring anything that is not
// an IP (link-layer addresses appear in the same slots).
func addrOf(a route.Addr) (netip.Addr, bool) {
	switch v := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(v.IP), true
	case *route.Inet6Addr:
		addr := netip.AddrFrom16(v.IP)
		return addr, true
	}
	return netip.Addr{}, false
}

// maskBits counts the leading ones of a netmask expressed as an address.
func maskBits(mask netip.Addr) int {
	bits := 0
	for _, b := range mask.AsSlice() {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) == 0 {
				return bits
			}
			bits++
		}
	}
	return bits
}

func ifaceNames() map[int]string {
	out := map[int]string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifaces {
		out[i.Index] = i.Name
	}
	return out
}

// RouteWatchSupported reports whether route-hijack detection works here.
func RouteWatchSupported() bool { return true }
