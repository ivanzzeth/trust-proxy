// Package detect is the detection engine: every routed (allowed) connection is
// recorded as an event, byte-counted, and scored against detection rules
// (threat-intel domain/IP match, abnormally large upload = possible exfil).
// The console reads these via /api/events.
package detect

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event is one observed egress connection plus its detection verdict.
type Event struct {
	ID          uint64   `json:"id"`
	Time        string   `json:"time"`
	Network     string   `json:"network"`
	Host        string   `json:"host"`
	Destination string   `json:"destination"`
	Source      string   `json:"source"`
	Process     string   `json:"process"`
	Rule        string   `json:"rule"`
	Outbound    string   `json:"outbound"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	Level       string   `json:"level"`             // "info" | "alert"
	Block       bool     `json:"block,omitempty"`   // high-confidence (threat-intel) => auto-block eligible
	Denied      bool     `json:"denied,omitempty"`  // routed to the block outbound (default-deny / blacklist)
	Reasons     []string `json:"reasons,omitempty"`
}

// Engine holds a ring buffer of recent events and the detection config.
type Engine struct {
	mu     sync.Mutex
	events []*Event
	cap    int
	seq    uint64

	uploadAlertBytes int64
	autoBlock        bool
	// static (manual) indicators
	threatDomains map[string]struct{}
	threatIPs     map[string]struct{}
	// feed-sourced indicators (replaced on each refresh)
	feedDomains map[string]struct{}
	feedIPs     map[string]struct{}

	// beaconing (periodic C2 heartbeat) detection
	now             func() time.Time // injectable clock (tests)
	beaconEnabled   bool
	beaconMinSample int
	beaconCV        float64       // max coefficient of variation to call it regular
	beaconMinIntvl  time.Duration // ignore bursts faster than this
	beaconMaxIntvl  time.Duration // ignore cadences slower than this
	beaconReAlert   time.Duration // don't re-alert the same dest within this
	beacons         map[string]*beaconState

	// DGA / DNS-tunnel scoring on observed domains
	dgaEnabled bool
	dnsParents map[string]*parentState
}

type beaconState struct {
	times     []time.Time
	lastAlert time.Time
}

type parentState struct {
	subs      map[string]struct{}
	lastAlert time.Time
}

const beaconWindow = 20 // per-destination connection timestamps kept

// New builds an engine keeping the last `capacity` events.
func New(capacity int) *Engine {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Engine{
		cap:              capacity,
		uploadAlertBytes: 10 << 20, // 10 MiB upload -> exfil alert
		threatDomains:    map[string]struct{}{},
		threatIPs:        map[string]struct{}{},
		feedDomains:      map[string]struct{}{},
		feedIPs:          map[string]struct{}{},
		now:              time.Now,
		beaconEnabled:    true,
		beaconMinSample:  6, // >=5 intervals
		beaconCV:         0.25,
		beaconMinIntvl:   5 * time.Second,
		beaconMaxIntvl:   2 * time.Hour,
		beaconReAlert:    10 * time.Minute,
		beacons:          map[string]*beaconState{},
		dgaEnabled:       true,
		dnsParents:       map[string]*parentState{},
	}
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

// SetAutoBlock toggles auto-disposal: alert connections are dropped.
func (e *Engine) SetAutoBlock(v bool) {
	e.mu.Lock()
	e.autoBlock = v
	e.mu.Unlock()
}

// AutoBlock reports whether auto-disposal is enabled.
func (e *Engine) AutoBlock() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.autoBlock
}

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

// SetUploadAlert sets the upload byte threshold for the exfil alert.
func (e *Engine) SetUploadAlert(bytes int64) {
	e.mu.Lock()
	e.uploadAlertBytes = bytes
	e.mu.Unlock()
}

// Track records a new connection event, runs connection-time detection, and
// returns the event (whose Upload/Download the caller updates as bytes flow).
func (e *Engine) Track(network, host, dst, src, process, rule, outbound string) *Event {
	e.mu.Lock()
	e.seq++
	now := e.now()
	ev := &Event{
		ID: e.seq, Time: now.Format(time.RFC3339), Network: network,
		Host: host, Destination: dst, Source: src, Process: process, Rule: rule, Outbound: outbound,
		Level: "info",
	}
	// Routed to the block outbound = denied by default-deny (or a blacklist rule).
	if strings.HasPrefix(outbound, "block/") {
		ev.Denied = true
	}
	// threat-intel match (domain + destination IP), against static + feed sets.
	// These are high-confidence => Block (auto-disposal eligible).
	if host != "" {
		h := strings.ToLower(host)
		_, s1 := e.threatDomains[h]
		_, s2 := e.feedDomains[h]
		if s1 || s2 {
			ev.Level = "alert"
			ev.Block = true
			ev.Reasons = append(ev.Reasons, "threat-intel domain match: "+host)
		}
	}
	if ip := hostOnly(dst); ip != "" {
		_, s1 := e.threatIPs[ip]
		_, s2 := e.feedIPs[ip]
		if s1 || s2 {
			ev.Level = "alert"
			ev.Block = true
			ev.Reasons = append(ev.Reasons, "threat-intel IP match: "+ip)
		}
	}
	// beaconing: periodic connections to the same destination = possible C2
	// heartbeat. Heuristic => alert only (NOT auto-blocked).
	if e.beaconEnabled {
		key := host
		if key == "" {
			key = hostOnly(dst)
		}
		if r := e.recordBeacon(key, now); r != "" {
			ev.Level = "alert"
			ev.Reasons = append(ev.Reasons, r)
		}
	}
	// DGA / DNS-tunnel scoring on the domain (heuristic => alert only).
	if e.dgaEnabled && host != "" {
		if rs := e.analyzeDomain(host, now); len(rs) > 0 {
			ev.Level = "alert"
			ev.Reasons = append(ev.Reasons, rs...)
		}
	}
	e.events = append(e.events, ev)
	if len(e.events) > e.cap {
		e.events = e.events[len(e.events)-e.cap:]
	}
	e.mu.Unlock()
	return ev
}

// RestoreEvents loads a previously persisted snapshot (newest-first, as produced
// by Events) back into the ring buffer so the audit log survives a restart.
func (e *Engine) RestoreEvents(evs []Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(evs) - 1; i >= 0; i-- { // append oldest-first
		cp := evs[i]
		e.events = append(e.events, &cp)
		if cp.ID > e.seq {
			e.seq = cp.ID
		}
	}
	if len(e.events) > e.cap {
		e.events = e.events[len(e.events)-e.cap:]
	}
}

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
	sld := labels[len(labels)-2]
	// DGA: long, high-entropy second-level label that is digit-heavy or
	// vowel-starved (kq3v9z7x1p2m.com), unlike real brands.
	if len(sld) >= 12 && shannon(sld) >= 3.8 && (digitRatio(sld) >= 0.25 || vowelRatio(sld) <= 0.2) {
		reasons = append(reasons, fmt.Sprintf("DGA-like domain %q (entropy %.1f) — possible malware C2", sld, shannon(sld)))
	}
	// Tunnel: a single long, high-entropy subdomain label encodes data.
	for _, lab := range labels[:len(labels)-2] {
		if len(lab) >= 25 && shannon(lab) >= 4.0 {
			reasons = append(reasons, fmt.Sprintf("long high-entropy subdomain label (%d chars) — possible DNS tunnel", len(lab)))
			break
		}
	}
	// Volume: many distinct subdomains under one parent within the window.
	if len(labels) >= 3 {
		parent := labels[len(labels)-2] + "." + labels[len(labels)-1]
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

// finalize is called when a connection closes: re-score with final byte counts.
func (e *Engine) finalize(ev *Event) {
	up := atomic.LoadInt64(&ev.Upload)
	e.mu.Lock()
	if e.uploadAlertBytes > 0 && up >= e.uploadAlertBytes {
		ev.Level = "alert"
		ev.Reasons = append(ev.Reasons, fmt.Sprintf("large upload %s (possible exfil)", humanBytes(up)))
	}
	e.mu.Unlock()
}

// Events returns a snapshot of recent events, newest first.
func (e *Engine) Events() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Event, 0, len(e.events))
	for i := len(e.events) - 1; i >= 0; i-- {
		ev := e.events[i]
		cp := *ev
		cp.Upload = atomic.LoadInt64(&ev.Upload)
		cp.Download = atomic.LoadInt64(&ev.Download)
		cp.Reasons = append([]string(nil), ev.Reasons...)
		out = append(out, cp)
	}
	return out
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func humanBytes(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10) + " B"
	}
	u := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n) / 1024
	i := 0
	for v >= 1024 && i < len(u)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, u[i])
}
