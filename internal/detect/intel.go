package detect

import "strings"

// SetFeedThreats replaces the feed-sourced indicator set (from a threat feed
// refresh). Static indicators from LoadThreats are kept separately.
func (e *Engine) SetFeedThreats(domains, ips []string) {
	dm := make(map[string]struct{}, len(domains))
	im := make(map[string]struct{}, len(ips))
	for _, d := range domains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			dm[d] = struct{}{}
		}
	}
	for _, ip := range ips {
		if ip = strings.TrimSpace(ip); ip != "" {
			im[ip] = struct{}{}
		}
	}
	e.mu.Lock()
	e.feedDomains, e.feedIPs = dm, im
	e.mu.Unlock()
}

// ThreatCounts returns (static+feed) indicator counts for status.
func (e *Engine) ThreatCounts() (domains, ips int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.threatDomains) + len(e.feedDomains), len(e.threatIPs) + len(e.feedIPs)
}

// LoadThreats adds C2/malware indicators (domains and IPs) to match against.
func (e *Engine) LoadThreats(domains, ips []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, d := range domains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			e.threatDomains[d] = struct{}{}
		}
	}
	for _, ip := range ips {
		if ip = strings.TrimSpace(ip); ip != "" {
			e.threatIPs[ip] = struct{}{}
		}
	}
}

// matchThreatLocked appends intel reasons onto ev and returns them.
// Caller must hold e.mu. High-confidence => Block.
func (e *Engine) matchThreatLocked(ev *Event, host, dst string) []string {
	var reasons []string
	if host != "" {
		h := strings.ToLower(host)
		_, s1 := e.threatDomains[h]
		_, s2 := e.feedDomains[h]
		if s1 || s2 {
			r := "threat-intel domain match: " + host
			ev.Level = "alert"
			ev.Block = true
			ev.Reasons = append(ev.Reasons, r)
			reasons = append(reasons, r)
		}
	}
	if ip := hostOnly(dst); ip != "" {
		_, s1 := e.threatIPs[ip]
		_, s2 := e.feedIPs[ip]
		if s1 || s2 {
			r := "threat-intel IP match: " + ip
			ev.Level = "alert"
			ev.Block = true
			ev.Reasons = append(ev.Reasons, r)
			reasons = append(reasons, r)
		}
	}
	return reasons
}
