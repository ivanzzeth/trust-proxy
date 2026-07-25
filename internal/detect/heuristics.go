package detect

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const beaconWindow = 20 // per-destination connection timestamps kept

type beaconState struct {
	times     []time.Time
	lastAlert time.Time
}

type parentState struct {
	subs      map[string]struct{}
	lastAlert time.Time
}

// SetBeaconing toggles beaconing detection.
func (e *Engine) SetBeaconing(v bool) {
	e.mu.Lock()
	e.beaconEnabled = v
	e.mu.Unlock()
}

// SetDGA toggles DGA / DNS-tunnel domain scoring.
func (e *Engine) SetDGA(v bool) {
	e.mu.Lock()
	e.dgaEnabled = v
	e.mu.Unlock()
}

// SetUploadAlert sets the upload byte threshold for the exfil alert.
func (e *Engine) SetUploadAlert(bytes int64) { e.uploadAlertBytes.Store(bytes) }

// recordBeacon appends a connection time for key and returns a non-empty alert
// reason when the inter-arrival pattern looks like a regular C2 heartbeat.
// Caller must hold e.mu.
func (e *Engine) recordBeacon(key string, now time.Time) string {
	if key == "" {
		return ""
	}
	// Bound memory: opportunistically drop destinations idle beyond the window.
	if len(e.beacons) > 4096 {
		for k, st := range e.beacons {
			if len(st.times) == 0 || now.Sub(st.times[len(st.times)-1]) > e.beaconMaxIntvl {
				delete(e.beacons, k)
			}
		}
	}
	bs := e.beacons[key]
	if bs == nil {
		bs = &beaconState{}
		e.beacons[key] = bs
	}
	bs.times = append(bs.times, now)
	if len(bs.times) > beaconWindow {
		bs.times = bs.times[len(bs.times)-beaconWindow:]
	}
	if len(bs.times) < e.beaconMinSample {
		return ""
	}
	intervals := make([]float64, 0, len(bs.times)-1)
	for i := 1; i < len(bs.times); i++ {
		intervals = append(intervals, bs.times[i].Sub(bs.times[i-1]).Seconds())
	}
	mean, cv := meanCV(intervals)
	if mean < e.beaconMinIntvl.Seconds() || mean > e.beaconMaxIntvl.Seconds() || cv > e.beaconCV {
		return ""
	}
	if !bs.lastAlert.IsZero() && now.Sub(bs.lastAlert) < e.beaconReAlert {
		return ""
	}
	bs.lastAlert = now
	return fmt.Sprintf("beaconing to %s: %d conns, ~%.0fs interval (cv %.2f) — possible C2", key, len(bs.times), mean, cv)
}

// analyzeDomain flags DGA-like registrable labels, long high-entropy subdomain
// labels (data-encoding = DNS tunnel), and a high count of distinct subdomains
// under one parent (tunneling / fast-flux). Heuristic; caller holds e.mu.
func (e *Engine) analyzeDomain(host string, now time.Time) []string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" || net.ParseIP(h) != nil {
		return nil
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return nil
	}
	var reasons []string

	// sld is the registrable label and parent its eTLD+1, resolved via the
	// public suffix list so multi-label TLDs (x.co.uk, x.com.cn) don't fall
	// back to treating "co"/"com" as the attacker-controlled label — that
	// silently skipped the real label on exactly the .com.cn domains this
	// gateway sees most. subLabels holds whatever sits left of the
	// registrable domain (empty when h has no subdomain).
	sld := labels[len(labels)-2]
	parent := sld
	if len(labels) >= 3 {
		parent = labels[len(labels)-2] + "." + labels[len(labels)-1]
	}
	subLabels := labels[:len(labels)-2]
	if etld1, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		parent = etld1
		if i := strings.IndexByte(etld1, '.'); i >= 0 {
			sld = etld1[:i]
		} else {
			sld = etld1
		}
		if rest := strings.TrimSuffix(h, "."+etld1); rest != h && rest != "" {
			subLabels = strings.Split(rest, ".")
		} else {
			subLabels = nil
		}
	}

	// DGA: long, high-entropy registrable label that is digit-heavy or
	// vowel-starved (kq3v9z7x1p2m.com), unlike real brands.
	if len(sld) >= 12 && shannon(sld) >= 3.8 && (digitRatio(sld) >= 0.25 || vowelRatio(sld) <= 0.2) {
		reasons = append(reasons, fmt.Sprintf("DGA-like domain %q (entropy %.1f) — possible malware C2", sld, shannon(sld)))
	}
	// Tunnel: a single long, high-entropy subdomain label encodes data.
	for _, lab := range subLabels {
		if len(lab) >= 25 && shannon(lab) >= 4.0 {
			reasons = append(reasons, fmt.Sprintf("long high-entropy subdomain label (%d chars) — possible DNS tunnel", len(lab)))
			break
		}
	}
	// Volume: many distinct subdomains under one parent within the window.
	if len(labels) >= 3 {
		if len(e.dnsParents) > 8192 {
			e.dnsParents = map[string]*parentState{} // coarse bound
		}
		ps := e.dnsParents[parent]
		if ps == nil {
			ps = &parentState{subs: map[string]struct{}{}}
			e.dnsParents[parent] = ps
		}
		if len(ps.subs) < 4096 {
			ps.subs[h] = struct{}{}
		}
		if len(ps.subs) >= 40 && (ps.lastAlert.IsZero() || now.Sub(ps.lastAlert) > 10*time.Minute) {
			ps.lastAlert = now
			reasons = append(reasons, fmt.Sprintf("%d distinct subdomains under %s — possible DNS tunneling / fast-flux", len(ps.subs), parent))
		}
	}
	return reasons
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	n := 0
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
		n++
	}
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

func digitRatio(s string) float64 {
	if s == "" {
		return 0
	}
	d := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			d++
		}
	}
	return float64(d) / float64(len(s))
}

func vowelRatio(s string) float64 {
	if s == "" {
		return 0
	}
	v := 0
	for _, r := range s {
		switch r {
		case 'a', 'e', 'i', 'o', 'u':
			v++
		}
	}
	return float64(v) / float64(len(s))
}

func meanCV(xs []float64) (mean, cv float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(len(xs))
	if mean == 0 {
		return 0, 0
	}
	var varsum float64
	for _, x := range xs {
		d := x - mean
		varsum += d * d
	}
	std := math.Sqrt(varsum / float64(len(xs)))
	return mean, std / mean
}
