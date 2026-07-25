package customrules

import (
	"net"
	"regexp"
	"strings"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// MatchesPermit reports whether host (SNI/domain) or destination IP is covered
// by an enabled custom rule that GrantsPermit. Packs (Cursor/Claude/…) open the
// L3 gate this way — detection's trustedDest MUST use the same set, or large
// uploads to pack domains get wrongly auto-blocked as exfil.
func MatchesPermit(rules Rules, host, destination string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	ipStr := destIP(destination)
	var ip net.IP
	if ipStr != "" {
		ip = net.ParseIP(ipStr)
	}
	for _, r := range rules.Rules {
		if !r.Enabled {
			continue
		}
		apitypes.NormalizeCustomRule(&r)
		if !r.GrantsPermit() {
			continue
		}
		v := strings.TrimSpace(r.Value)
		if v == "" {
			continue
		}
		switch r.Match {
		case apitypes.CustomMatchDomain:
			if h != "" && h == strings.ToLower(v) {
				return true
			}
		case apitypes.CustomMatchDomainSuffix:
			suf := strings.ToLower(v)
			if h != "" && (h == suf || strings.HasSuffix(h, "."+suf)) {
				return true
			}
		case apitypes.CustomMatchKeyword:
			if h != "" && strings.Contains(h, strings.ToLower(v)) {
				return true
			}
		case apitypes.CustomMatchRegex:
			if h == "" {
				continue
			}
			re, err := regexp.Compile("(?i)" + v)
			if err == nil && re.MatchString(h) {
				return true
			}
		case apitypes.CustomMatchIPCIDR:
			if ip == nil {
				continue
			}
			if strings.Contains(v, "/") {
				_, n, err := net.ParseCIDR(v)
				if err == nil && n.Contains(ip) {
					return true
				}
			} else if p := net.ParseIP(v); p != nil && p.Equal(ip) {
				return true
			}
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
