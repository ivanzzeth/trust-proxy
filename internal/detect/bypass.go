package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Encrypted-DNS bypass observation.
//
// A client that speaks DoH/DoT to a public resolver takes its name resolution
// out of this gateway entirely: the query-level detectors see nothing, and the
// domain-based Permit gate sees only an IP. Browsers do this by default in some
// regions. Detecting it is the prerequisite for deciding what to do about it —
// and this build only reports.
//
// Kept as a list rather than a rule set because it must work with no network:
// these are the endpoints a client reaches for when it wants its own resolver.

// dohEndpoints are well-known public encrypted-DNS endpoints (domain suffixes).
var dohEndpoints = []string{
	"dns.google", "dns64.dns.google",
	"cloudflare-dns.com", "mozilla.cloudflare-dns.com", "one.one.one.one", "security.cloudflare-dns.com",
	"dns.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
	"doh.opendns.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
	"dns.adguard-dns.com", "unfiltered.adguard-dns.com", "dns.alidns.com", "doh.pub", "dot.pub",
	"doh.360.cn", "doh.dns.sb", "dns.twnic.tw", "doh.mullvad.net",
}

// dohAddrs are the addresses those services answer on, for clients that skip
// the name and dial the IP directly.
var dohAddrs = []string{
	"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
	"208.67.222.222", "208.67.220.220", "223.5.5.5", "223.6.6.6", "119.29.29.29",
	"2001:4860:4860::8888", "2606:4700:4700::1111", "2620:fe::fe",
}

// checkEncryptedDNSBypass returns a reason when a connection looks like a client
// resolving through someone else's encrypted DNS. Ports matter: 443 is DoH/DoQ,
// 853 is DoT. Caller holds e.mu.
//
// A client configured to use public DoH keeps doing it: measured on a real box,
// one WARP-style client produced 614 connections to two endpoints in an hour.
// That is a standing condition, not 614 findings — so it is reported once per
// (client, endpoint) per cooldown, exactly like a beaconing cadence.
func (e *Engine) checkEncryptedDNSBypassLocked(host, dst, process string, now time.Time) string {
	port := portOf(dst)
	if port != "443" && port != "853" {
		return ""
	}
	// Our own resolver dials these on purpose; the gateway is not bypassing itself.
	if process != "" && strings.Contains(strings.ToLower(process), "trust-proxy") {
		return ""
	}
	// hostOnly: callers that never sniffed a domain hand us the destination, and
	// a trailing ":443" would make every suffix comparison below miss.
	target := hostOnly(strings.ToLower(strings.TrimSuffix(host, ".")))
	matched := ""
	for _, d := range dohEndpoints {
		if target == d || strings.HasSuffix(target, "."+d) {
			matched = d
			break
		}
	}
	if matched == "" {
		ip := hostOnly(dst)
		for _, a := range dohAddrs {
			if ip == a {
				matched = a
				break
			}
		}
	}
	if matched == "" {
		return ""
	}
	what := "DoH"
	if port == "853" {
		what = "DoT"
	}
	if !e.bypassReadyLocked(hostOnly(dst)+"|"+matched, now) {
		return ""
	}
	return fmt.Sprintf(
		"%s to %s: this client resolves names outside the gateway, so query-level detection and domain policy do not see it",
		what, matched)
}

// bypassReadyLocked applies the per-endpoint cooldown. Caller holds e.mu.
func (e *Engine) bypassReadyLocked(key string, now time.Time) bool {
	if e.bypassSeen == nil {
		e.bypassSeen = map[string]time.Time{}
	}
	window := time.Duration(e.dnsBypassReAlertSec) * time.Second
	if last, ok := e.bypassSeen[key]; ok && now.Sub(last) < window {
		return false
	}
	if len(e.bypassSeen) > 4096 {
		for k, t := range e.bypassSeen {
			if now.Sub(t) > window {
				delete(e.bypassSeen, k)
			}
		}
	}
	e.bypassSeen[key] = now
	return true
}

// portOf returns the port part of host:port, or "".
func portOf(dst string) string {
	i := strings.LastIndexByte(dst, ':')
	if i < 0 {
		return ""
	}
	return dst[i+1:]
}

// NoteECH records that a destination published an Encrypted Client Hello config.
// With ECH the ClientHello carries a cover domain, so the SNI this gateway's
// Permit gate matches on is no longer the real one — a domain allow-list quietly
// stops meaning what it says. Counted rather than alerted per query: the point is
// "how much of my policy surface is going opaque", not one event.
func (e *Engine) NoteECH(name, client string) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.echDomains == nil {
		e.echDomains = map[string]int{}
	}
	if len(e.echDomains) < echMax {
		e.echDomains[name]++
	}
	e.echTotal++
}

// ECHStats reports how many answers carried an ECH config and for which names.
func (e *Engine) ECHStats(top int) (total int64, names []string) {
	if top <= 0 {
		top = 20
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for n := range e.echDomains {
		names = append(names, n)
		if len(names) >= top {
			break
		}
	}
	sort.Strings(names)
	return e.echTotal, names
}

const echMax = 2048
