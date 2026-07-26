package detect

import (
	"fmt"
	"net/netip"
)

// LocalNet exposure (TunnelCrack).
//
// The gateway treats every RFC1918 / CGNAT address as "LAN": always direct, and
// always inside the Permit set. A hostile network only has to claim one of those
// ranges for a public service and its traffic leaves outside the tunnel and
// around the gate — the machine believes it is talking to the local network.
//
// The engine cannot see the routing table, so it asks: is this destination
// actually on-link for one of this host's interfaces? A "private" address that
// is not in any real local prefix is the shape of that attack.

// SetLocalNetCheck registers the predicate that answers "is this address really
// on-link here" (internal/netwatch). Without it the check is skipped, because
// guessing would either alert on every LAN print job or on nothing.
func (e *Engine) SetLocalNetCheck(fn func(netip.Addr) bool) {
	e.mu.Lock()
	e.isOnLink = fn
	e.mu.Unlock()
}

// checkLocalNet returns a reason when dst is a private address that no local
// interface actually covers. Caller holds e.mu.
func (e *Engine) checkLocalNetLocked(dst string) string {
	if e.isOnLink == nil {
		return ""
	}
	host := hostOnly(dst)
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	if !isPrivateish(addr) || e.isOnLink(addr) {
		return ""
	}
	return fmt.Sprintf(
		"destination %s is treated as LAN (direct, and inside the Permit set) but is not on any local subnet — a network claiming this range pulls traffic out of the tunnel (TunnelCrack LocalNet)",
		addr)
}

// isPrivateish covers what the gateway's LAN bypass covers: RFC1918, CGNAT,
// link-local and unique-local v6.
func isPrivateish(a netip.Addr) bool {
	if a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback() {
		return true
	}
	if a.Is4() {
		b := a.As4()
		return b[0] == 100 && b[1] >= 64 && b[1] <= 127 // 100.64/10
	}
	return a.As16()[0]&0xfe == 0xfc // fc00::/7
}
