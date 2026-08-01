package gateway

import "runtime"

// tunPrivateRouteExcludes returns CIDRs that must never be pulled into the TUN
// routing table (sing-box route_exclude_address).
//
// On Darwin (and Windows) the kernel reaches the LAN via a more-specific
// on-link route on the physical NIC. The TUN catch-alls (128.0/1 + 0/1 …) still
// cover every RFC1918 range, so if that on-link route disappears for a moment
// — Wi-Fi sleep, DHCP renew, hot-reload race — LAN destinations fall into the
// tunnel, get routed to `direct`, and hang until the dial timeout. Measured on
// a live Mac: ssh to 192.168.31.72 under TUN became four consecutive
// direct/direct entries at exactly 5000ms / 0 bytes, while the same path was
// fine once the on-link route was back. Carving privateCIDRs out of the TUN
// routes matches the data-plane policy (LAN is always direct) and keeps the
// LAN reachable even when the on-link route flaps.
//
// Linux is the opposite problem: Docker/containerd/K8s Pod egress lives in
// 10/8 and 172.16/12, and auto_redirect exists specifically to capture it.
// Excluding privateCIDRs there would silently disable the feature e2e-tun
// asserts. So Linux returns nil.
func tunPrivateRouteExcludes() []string {
	if runtime.GOOS == "linux" {
		return nil
	}
	return PrivateCIDRs()
}
