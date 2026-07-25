// Package detect is the detection engine: every routed connection is recorded,
// byte-counted, and scored (threat-intel, exfil, beacon, DGA). Alerts emit
// Detection records into an optional durable store; the console reads them via
// /api/detections. Connection history still flows through Event finalize.
package detect

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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

	onFinalize   func(Event)     // completed connection (history sink)
	onDetection  func(Detection) // alert findings (detections store)
	trustedDest  func(host, destination string) bool
	onBan        func(domain, ip, reason string)
}

// SetOnFinalize registers a sink invoked once per connection when it closes,
// with final byte counts. Set before traffic starts (not synchronized).
func (e *Engine) SetOnFinalize(fn func(Event)) { e.onFinalize = fn }

// SetOnDetection registers a sink for each Detection finding (intel/exfil/…).
func (e *Engine) SetOnDetection(fn func(Detection)) { e.onDetection = fn }

// SetTrustedDest registers a predicate: true => destination is on the Permit
// whitelist (large upload will not auto-block / auto-ban).
func (e *Engine) SetTrustedDest(fn func(host, destination string) bool) {
	e.trustedDest = fn
}

// SetOnBan registers a sink that adds an auto-blocked destination to the
// deny-list (domain and/or IP). Called once per ban decision.
func (e *Engine) SetOnBan(fn func(domain, ip, reason string)) {
	e.onBan = fn
}

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

	var pending []Detection
	if rs := e.matchThreatLocked(ev, host, dst); len(rs) > 0 {
		pending = append(pending, e.makeDetectionLocked(KindIntel, e.disposalActionLocked(), ev, rs))
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
			pending = append(pending, e.makeDetectionLocked(KindBeacon, ActionAlert, ev, []string{r}))
		}
	}
	// DGA / DNS-tunnel scoring on the domain (heuristic => alert only).
	if e.dgaEnabled && host != "" {
		if rs := e.analyzeDomain(host, now); len(rs) > 0 {
			ev.Level = "alert"
			ev.Reasons = append(ev.Reasons, rs...)
			pending = append(pending, e.makeDetectionLocked(KindDGA, ActionAlert, ev, rs))
		}
	}
	e.events = append(e.events, ev)
	if len(e.events) > e.cap {
		e.events = e.events[len(e.events)-e.cap:]
	}
	e.mu.Unlock()

	for _, d := range pending {
		e.fireDetection(d)
	}
	return ev
}

// disposalActionLocked: auto-block + ban sink => banned; auto-block only => blocked; else alert.
// Caller holds e.mu.
func (e *Engine) disposalActionLocked() Action {
	if !e.autoBlock {
		return ActionAlert
	}
	if e.onBan == nil {
		return ActionBlocked
	}
	return ActionBanned
}

func (e *Engine) makeDetectionLocked(kind Kind, action Action, ev *Event, reasons []string) Detection {
	return Detection{
		Time:        ev.Time,
		Kind:        kind,
		Host:        ev.Host,
		Destination: ev.Destination,
		Process:     ev.Process,
		Upload:      atomic.LoadInt64(&ev.Upload),
		Download:    atomic.LoadInt64(&ev.Download),
		Action:      action,
		Reasons:     append([]string(nil), reasons...),
		EventID:     ev.ID,
	}
}

func (e *Engine) fireDetection(d Detection) {
	if e.onDetection != nil {
		e.onDetection(d)
	}
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

// finalize is called when a connection closes: re-score with final byte counts.
func (e *Engine) finalize(ev *Event) {
	up := atomic.LoadInt64(&ev.Upload)
	e.mu.Lock()
	thresh := e.uploadAlertBytes
	auto := e.autoBlock
	e.mu.Unlock()
	if thresh > 0 && up >= thresh {
		e.mu.Lock()
		ev.Level = "alert"
		reason := fmt.Sprintf("large upload %s (possible exfil)", humanBytes(up))
		if !hasReason(ev.Reasons, "large upload") {
			ev.Reasons = append(ev.Reasons, reason)
		}
		already := ev.exfilEmitted
		e.mu.Unlock()
		// Non-whitelist large upload = high-confidence exfil when auto-block is on.
		// Includes LAN/private destinations — a local C2 / pivot is still exfil.
		if auto && !ev.Denied && !e.isTrusted(ev) {
			ev.Block = true
			e.banEvent(ev, "large upload to non-whitelist destination")
			if !already {
				e.emitExfil(ev, e.exfilAction(), reason)
			}
		} else if !already {
			e.emitExfil(ev, ActionAlert, reason)
		}
	}
	if e.onFinalize != nil {
		cp := *ev
		cp.Upload = up
		cp.Download = atomic.LoadInt64(&ev.Download)
		cp.Reasons = append([]string(nil), ev.Reasons...)
		e.onFinalize(cp)
	}
}

func (e *Engine) exfilAction() Action {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.disposalActionLocked()
}

func (e *Engine) emitExfil(ev *Event, action Action, reason string) {
	e.mu.Lock()
	ev.exfilEmitted = true
	d := e.makeDetectionLocked(KindExfil, action, ev, []string{reason})
	e.mu.Unlock()
	e.fireDetection(d)
}

func hasReason(rs []string, prefix string) bool {
	for _, r := range rs {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

func (e *Engine) isTrusted(ev *Event) bool {
	if e.trustedDest == nil {
		return false
	}
	return e.trustedDest(ev.Host, ev.Destination)
}

// BanFromEvent adds the event's destination to the deny-list (threat-intel or
// exfil path). Safe to call multiple times; onBan may de-dupe in the store.
func (e *Engine) BanFromEvent(ev *Event, reason string) {
	e.banEvent(ev, reason)
}

func (e *Engine) banEvent(ev *Event, reason string) {
	if e.onBan == nil || ev == nil {
		return
	}
	domain := strings.ToLower(strings.TrimSpace(ev.Host))
	if net.ParseIP(domain) != nil {
		domain = "" // host was bare IP
	}
	ip := hostOnly(ev.Destination)
	if ip == "" && domain == "" {
		return
	}
	e.onBan(domain, ip, reason)
}

// checkExfilMidStream is called from the byte counter when upload grows. If the
// threshold is crossed for a non-whitelist destination and auto-block is on,
// marks the event Block-eligible and bans. Returns true when the caller should
// kill the connection now.
func (e *Engine) checkExfilMidStream(ev *Event, up int64) bool {
	e.mu.Lock()
	thresh := e.uploadAlertBytes
	auto := e.autoBlock
	e.mu.Unlock()
	if !auto || thresh <= 0 || up < thresh || ev.Denied || ev.Block {
		return false
	}
	if e.isTrusted(ev) {
		return false
	}
	reason := fmt.Sprintf("large upload %s (possible exfil)", humanBytes(up))
	e.mu.Lock()
	ev.Level = "alert"
	ev.Block = true
	if !hasReason(ev.Reasons, "large upload") {
		ev.Reasons = append(ev.Reasons, reason)
	}
	already := ev.exfilEmitted
	action := e.disposalActionLocked()
	e.mu.Unlock()
	e.banEvent(ev, "large upload to non-whitelist destination")
	if !already {
		e.emitExfil(ev, action, reason)
	}
	return true
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
