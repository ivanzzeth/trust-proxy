package whitelist

import (
	"net"
	"strings"
)

// Matches reports whether host (SNI/domain) or the destination address is on
// the Permit whitelist (domains as suffix match, IPs as exact/CIDR). Used by
// the detection engine to decide whether a large upload is "expected".
func Matches(r Rules, host, destination string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	ipStr := destIP(destination)
	for _, d := range r.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, "*?") {
			// Glob entries: only exact equality after stripping a leading *.
			if strings.HasPrefix(d, "*.") {
				suf := d[2:]
				if h == suf || strings.HasSuffix(h, "."+suf) {
					return true
				}
			}
			continue
		}
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	if ipStr == "" {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, entry := range r.IPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, n, err := net.ParseCIDR(entry)
			if err == nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if p := net.ParseIP(entry); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}

func destIP(destination string) string {
	if destination == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(destination); err == nil {
		return h
	}
	return destination
}
