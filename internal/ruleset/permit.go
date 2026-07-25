package ruleset

import (
	"io"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// permitIndex is the decoded, matchable form of one permit-granting rule set.
// domain/domain_suffix entries collapse into one suffix set: checking a query
// host's own progressively-shorter suffixes against it is O(labels-in-host),
// not O(entries-in-set) — so even a 100k-entry geosite list stays cheap to
// query (unlike scanning the whole entry list per lookup).
type permitIndex struct {
	suffixes map[string]struct{}
	keywords []string
	regexes  []*regexp.Regexp
	cidrs    []*net.IPNet
}

var (
	permitMu    sync.Mutex
	permitCache = map[string]permitIndex{} // keyed by rule-set tag
)

// WarmPermitCache decodes every enabled, permit-granting rule set in sets and
// replaces the in-memory index MatchesPermit reads. This does network I/O
// (via get; nil = direct fetch) and MUST be called off the connection hot
// path — MatchesPermit only ever reads the cache, it never fetches, so a
// slow or unreachable rule-set source can't stall a live connection's
// exfil/trust check. Call it once at startup and again whenever the rule-set
// store changes; a stale cache just means a just-added pack's domains aren't
// recognized as trusted until the next warm, which is the same "fails closed"
// behavior as before this cache existed.
func WarmPermitCache(sets Sets, get func(url string) (io.ReadCloser, error)) {
	next := map[string]permitIndex{}
	for _, rs := range sets.Sets {
		if !rs.Enabled || rs.Tag == "" || !apitypes.RuleRoleGrantsPermit(rs.Role) {
			continue
		}
		entries, err := Decode(rs, get)
		if err != nil {
			continue // best-effort: leave this tag absent from the cache
		}
		idx := permitIndex{suffixes: map[string]struct{}{}}
		for _, e := range entries {
			switch e.Kind {
			case "domain", "domain_suffix":
				idx.suffixes[strings.ToLower(e.Value)] = struct{}{}
			case "domain_keyword":
				idx.keywords = append(idx.keywords, strings.ToLower(e.Value))
			case "domain_regex":
				if re, err := regexp.Compile("(?i)" + e.Value); err == nil {
					idx.regexes = append(idx.regexes, re)
				}
			case "ip_cidr":
				v := e.Value
				if !strings.Contains(v, "/") {
					if strings.Contains(v, ":") {
						v += "/128"
					} else {
						v += "/32"
					}
				}
				if _, ipnet, err := net.ParseCIDR(v); err == nil {
					idx.cidrs = append(idx.cidrs, ipnet)
				}
			}
		}
		next[rs.Tag] = idx
	}
	permitMu.Lock()
	permitCache = next
	permitMu.Unlock()
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

// MatchesPermit reports whether host (SNI/domain) or destination is covered
// by any rule set currently in the warm cache (see WarmPermitCache). This is
// the rule-set-role half of the L3 Permit gate — detection's trustedDest must
// also check this (alongside whitelist.Matches and customrules.MatchesPermit)
// or a large upload to a pack whose Permit comes entirely from a rule-set
// role (e.g. Slack/Notion/China-wide, whose custom rules are empty) gets
// wrongly auto-blocked/banned as exfiltration.
func MatchesPermit(host, destination string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	var ip net.IP
	if ipStr := destIP(destination); ipStr != "" {
		ip = net.ParseIP(ipStr)
	}
	permitMu.Lock()
	defer permitMu.Unlock()
	for _, idx := range permitCache {
		if h != "" {
			for d := h; ; {
				if _, ok := idx.suffixes[d]; ok {
					return true
				}
				i := strings.IndexByte(d, '.')
				if i < 0 {
					break
				}
				d = d[i+1:]
			}
			for _, kw := range idx.keywords {
				if strings.Contains(h, kw) {
					return true
				}
			}
			for _, re := range idx.regexes {
				if re.MatchString(h) {
					return true
				}
			}
		}
		if ip != nil {
			for _, cidr := range idx.cidrs {
				if cidr.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}
