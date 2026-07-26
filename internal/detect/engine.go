// Package detect is the detection engine: every routed connection is recorded,
// byte-counted, and scored (threat-intel, exfil, beacon, DGA). Alerts emit
// Detection records into an optional durable store; the console reads them via
// /api/detections. Connection history still flows through Event finalize.
package detect

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Engine holds a ring buffer of recent events and the detection config.
type Engine struct {
	mu     sync.Mutex
	events []*Event
	cap    int
	seq    uint64

	// uploadAlertBytes and autoBlock are read lock-free on the per-Read()
	// hot path (checkExfilMidStream), so they're atomics rather than fields
	// guarded by mu — a mutex there would serialize every connection's reads
	// on one lock under concurrent throughput.
	uploadAlertBytes atomic.Int64
	autoBlock        atomic.Bool
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

	beaconReAlertFactor int

	// DGA / DNS-tunnel scoring on observed domains
	dgaEnabled        bool
	dgaMinLabelLen    int
	dgaMinEntropy     float64
	tunnelMinLabelLen int
	tunnelMinEntropy  float64
	subdomainAlertAt  int
	dnsParents        map[string]*parentState

	// exfil shaping: a big upload is only interesting when it is lopsided or the
	// destination is new. seen tracks first-contact times (bounded).
	exfilMinRatio     float64
	exfilNewDestHours int
	seen              map[string]time.Time

	// query-level observation (see query.go)
	queryWindowSec  int
	queryNXBurst    int
	queryParentRate int
	queryOddTypeAt  int
	queryTotal      int64
	queryNX         int64
	queryOdd        int64
	nxWindows       map[string]*queryWindow
	parentWindows   map[string]*queryWindow

	dnsBypassEnabled    bool
	dnsBypassReAlertSec int
	bypassSeen          map[string]time.Time
	ja4Enabled          bool
	ja4LearnMinutes     int
	ja4Start            time.Time
	fingerprints        map[string]*fingerprintState
	echDomains          map[string]int
	echTotal            int64

	// isOnLink answers "is this address really on a local subnet" (netwatch).
	isOnLink func(netip.Addr) bool

	// disposalReady gates auto-ban: nil = always ready. See RequireWarmPermit.
	disposalReady func() bool

	onFinalize  func(Event)     // completed connection (history sink)
	onDetection func(Detection) // alert findings (detections store)
	trustedDest func(host, destination string) bool
	onBan       func(domain, ip, reason string)
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

// EmitDetection publishes a finding produced outside Track/finalize (the DNS
// query path). Keeps the sink in one place so persistence and the console see
// query-level findings exactly like connection-level ones.
func (e *Engine) EmitDetection(d Detection) { e.fireDetection(d) }

// SetDisposalReady registers a predicate consulted before auto-ban: false means
// "the policy picture is not complete yet, do not dispose". Alerts are never
// gated by it — reporting fails open, disposal fails safe.
func (e *Engine) SetDisposalReady(fn func() bool) {
	e.mu.Lock()
	e.disposalReady = fn
	e.mu.Unlock()
}

// canDispose reports whether auto-ban may act right now.
func (e *Engine) canDispose() bool {
	e.mu.Lock()
	fn := e.disposalReady
	e.mu.Unlock()
	return fn == nil || fn()
}

// ApplyConfig swaps in operator-tuned thresholds (see internal/detectcfg).
// Safe to call while traffic flows; in-flight state (cadence windows, first-seen
// map) is kept so a settings change doesn't blind the engine.
func (e *Engine) ApplyConfig(c apitypes.DetectionConfig) {
	c = withEngineDefaults(c)
	e.mu.Lock()
	e.beaconEnabled = c.BeaconEnabled
	e.beaconMinSample = c.BeaconMinSample
	e.beaconCV = c.BeaconCV
	e.beaconMinIntvl = time.Duration(c.BeaconMinInterval) * time.Second
	e.beaconMaxIntvl = time.Duration(c.BeaconMaxInterval) * time.Second
	e.beaconReAlert = time.Duration(c.BeaconReAlert) * time.Second
	e.beaconReAlertFactor = c.BeaconReAlertFactor
	e.dgaEnabled = c.DGAEnabled
	e.dgaMinLabelLen = c.DGAMinLabelLen
	e.dgaMinEntropy = c.DGAMinEntropy
	e.tunnelMinLabelLen = c.TunnelMinLabelLen
	e.tunnelMinEntropy = c.TunnelMinEntropy
	e.subdomainAlertAt = c.SubdomainAlertAt
	e.exfilMinRatio = c.ExfilMinRatio
	e.exfilNewDestHours = c.ExfilNewDestHours
	e.queryWindowSec = c.QueryWindowSec
	e.queryNXBurst = c.QueryNXBurst
	e.queryParentRate = c.QueryParentRate
	e.queryOddTypeAt = c.QueryOddTypeAt
	e.dnsBypassEnabled = c.DNSBypassDetect
	e.dnsBypassReAlertSec = c.DNSBypassReAlertSec
	e.ja4Enabled = c.JA4Enabled
	e.ja4LearnMinutes = c.JA4LearnMinutes
	e.mu.Unlock()
	e.uploadAlertBytes.Store(c.ExfilUploadBytes)
	e.autoBlock.Store(c.AutoBlock)
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
	e := &Engine{
		cap:                 capacity,
		threatDomains:       map[string]struct{}{},
		threatIPs:           map[string]struct{}{},
		feedDomains:         map[string]struct{}{},
		feedIPs:             map[string]struct{}{},
		now:                 time.Now,
		beaconEnabled:       true,
		beaconMinSample:     6, // >=5 intervals
		beaconCV:            0.25,
		beaconMinIntvl:      5 * time.Second,
		beaconMaxIntvl:      2 * time.Hour,
		beaconReAlert:       10 * time.Minute,
		beacons:             map[string]*beaconState{},
		dgaEnabled:          true,
		dnsParents:          map[string]*parentState{},
		seen:                map[string]time.Time{},
		dnsBypassEnabled:    true,
		dnsBypassReAlertSec: 3600,
		ja4Enabled:          true,
		ja4LearnMinutes:     1440,
		nxWindows:           map[string]*queryWindow{},
		parentWindows:       map[string]*queryWindow{},
	}
	def := defaultTunables()
	e.beaconReAlertFactor = def.beaconReAlertFactor
	e.dgaMinLabelLen = def.dgaMinLabelLen
	e.dgaMinEntropy = def.dgaMinEntropy
	e.tunnelMinLabelLen = def.tunnelMinLabelLen
	e.tunnelMinEntropy = def.tunnelMinEntropy
	e.subdomainAlertAt = def.subdomainAlertAt
	e.exfilMinRatio = def.exfilMinRatio
	e.exfilNewDestHours = def.exfilNewDestHours
	e.queryWindowSec = def.queryWindowSec
	e.queryNXBurst = def.queryNXBurst
	e.queryParentRate = def.queryParentRate
	e.queryOddTypeAt = def.queryOddTypeAt
	e.uploadAlertBytes.Store(10 << 20) // 10 MiB upload -> exfil alert
	return e
}

// SetAutoBlock toggles auto-disposal: alert connections are dropped.
func (e *Engine) SetAutoBlock(v bool) { e.autoBlock.Store(v) }

// AutoBlock reports whether auto-disposal is enabled.
func (e *Engine) AutoBlock() bool { return e.autoBlock.Load() }

// Track records a new connection event, runs connection-time detection, and
// returns the event (whose Upload/Download the caller updates as bytes flow).
func (e *Engine) Track(network, host, dst, src, process, rule, outbound string) *Event {
	return e.TrackWithFingerprint(network, host, dst, src, process, rule, outbound, "")
}

// TrackWithFingerprint is Track plus the client's TLS fingerprint, when sniffing
// produced one (see internal/ja4).
func (e *Engine) TrackWithFingerprint(network, host, dst, src, process, rule, outbound, ja4 string) *Event {
	// Resolved before the lock: trustedDest is a caller-supplied predicate that
	// walks the whitelist / pack / rule-set indexes under their own locks. Running
	// it inside e.mu would serialize every connection behind those lookups and
	// invites a lock cycle back into the engine (finalize takes the same care).
	trusted := e.trustedHostDest(host, dst)
	e.mu.Lock()
	e.seq++
	now := e.now()
	ev := &Event{
		ID: e.seq, Time: now.Format(time.RFC3339), Network: network,
		Host: host, Destination: dst, Source: src, Process: process, Rule: rule, Outbound: outbound,
		JA4: ja4, Level: "info", openedAt: now,
	}
	// Routed to the block outbound = denied by default-deny (or a blacklist rule).
	if strings.HasPrefix(outbound, "block/") {
		ev.Denied = true
	}

	var pending []Detection
	if rs := e.matchThreatLocked(ev, host, dst); len(rs) > 0 {
		pending = append(pending, e.makeDetectionLocked(KindIntel, e.disposalActionLocked(), ev, rs))
	}
	// Heuristics never alert on a destination the operator explicitly Permitted:
	// a heartbeat to (or a big upload to) something you approved is the approved
	// behaviour, and drowning the real findings in it is how a detector becomes
	// wallpaper. Threat-intel hits above are deliberately NOT gated this way — a
	// permitted domain turning up on a feed is precisely what must still shout.
	// beaconing: periodic connections to the same destination = possible C2
	// heartbeat. Heuristic => alert only (NOT auto-blocked).
	if e.beaconEnabled && !trusted {
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
	// An unfamiliar TLS stack is worth naming even when the destination is not:
	// fingerprints keep working after ECH hides the name the Permit gate uses.
	if !trusted {
		if r := e.recordFingerprintLocked(ja4, host, process, now); r != "" {
			ev.Level = "alert"
			ev.Reasons = append(ev.Reasons, r)
			pending = append(pending, e.makeDetectionLocked(KindJA4, ActionAlert, ev, []string{r}))
		}
	} else {
		e.recordFingerprintLocked(ja4, host, process, now)
	}
	// A client using its own encrypted DNS takes resolution out of this gateway.
	if e.dnsBypassEnabled {
		if r := e.checkEncryptedDNSBypassLocked(host, dst, process, now); r != "" {
			ev.Level = "alert"
			ev.Reasons = append(ev.Reasons, r)
			pending = append(pending, e.makeDetectionLocked(KindDNSBypass, ActionAlert, ev, []string{r}))
		}
	}
	// LocalNet: a "LAN" destination that is not on any real local subnet is the
	// shape of a network lying about its scope to pull traffic out of the tunnel.
	if r := e.checkLocalNetLocked(dst); r != "" {
		ev.Level = "alert"
		ev.Reasons = append(ev.Reasons, r)
		pending = append(pending, e.makeDetectionLocked(KindLocalNet, ActionAlert, ev, []string{r}))
	}
	// DGA / DNS-tunnel scoring on the domain (heuristic => alert only).
	if e.dgaEnabled && host != "" && !trusted {
		if rs := e.analyzeDomain(host, now); len(rs) > 0 {
			ev.Level = "alert"
			ev.Reasons = append(ev.Reasons, rs...)
			pending = append(pending, e.makeDetectionLocked(KindDGA, ActionAlert, ev, rs))
		}
	}
	e.noteSeenLocked(dstKey(host, dst), now)
	// Also key by address: the host route watcher asks "did we dial this IP?" to
	// tell sing-box's own escape routes from injected ones.
	if ip := hostOnly(dst); ip != "" {
		e.noteSeenLocked(ip, now)
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
	if !e.autoBlock.Load() {
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
		User:        ev.User,
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

// latencyBreakdown derives human-meaningful phase durations (ms) from a
// TimingSource's raw timestamps. Returns all zero if t is nil (no timing was
// ever attached — e.g. UDP) or a phase's timestamps aren't both set.
func latencyBreakdown(t TimingSource) (dnsMs, connectMs, tlsMs int64) {
	if t == nil {
		return 0, 0, 0
	}
	dnsStart, dnsDone := t.DNSStartTime(), t.DNSDoneTime()
	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		dnsMs = dnsDone.Sub(dnsStart).Milliseconds()
	}
	connectFrom := t.DialStartTime()
	if !dnsDone.IsZero() {
		connectFrom = dnsDone
	}
	tcpDone, tlsDone, connectDone := t.TCPDoneTime(), t.TLSDoneTime(), t.ConnectDoneTime()
	switch {
	case !tcpDone.IsZero() && !tlsDone.IsZero() && !connectFrom.IsZero():
		// TLS-capable outbound: split TCP-connect from TLS-handshake.
		connectMs = tcpDone.Sub(connectFrom).Milliseconds()
		tlsMs = tlsDone.Sub(tcpDone).Milliseconds()
	case !connectDone.IsZero() && !connectFrom.IsZero():
		// No TLS split available (non-TLS outbound, or a protocol whose
		// handshake isn't reported as a separate phase) — one combined number.
		connectMs = connectDone.Sub(connectFrom).Milliseconds()
	}
	return dnsMs, connectMs, tlsMs
}

// finalize is called when a connection closes: re-score with final byte counts.
func (e *Engine) finalize(ev *Event) {
	up := atomic.LoadInt64(&ev.Upload)
	dur := e.now().Sub(ev.openedAt).Milliseconds()
	dnsMs, connectMs, tlsMs := latencyBreakdown(ev.timing)
	e.mu.Lock()
	ev.DurationMS = dur
	ev.DNSMs = dnsMs
	ev.ConnectMs = connectMs
	ev.TLSMs = tlsMs
	e.mu.Unlock()
	thresh := e.uploadAlertBytes.Load()
	auto := e.autoBlock.Load()
	if thresh > 0 && up >= thresh && e.exfilShaped(ev, up) {
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
		if auto && !ev.Denied && !e.isTrusted(ev) && e.canDispose() {
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
	if ev == nil {
		return false
	}
	return e.trustedHostDest(ev.Host, ev.Destination)
}

// trustedHostDest reports whether the operator explicitly Permitted this
// destination. Must be called WITHOUT e.mu held (see Track).
func (e *Engine) trustedHostDest(host, destination string) bool {
	if e.trustedDest == nil {
		return false
	}
	return e.trustedDest(host, destination)
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
	// Lock-free fast path: this runs on every Read() of every connection, so
	// the overwhelmingly common case (auto-block off, or still under
	// threshold) must not take e.mu — that would serialize all concurrent
	// connections' reads on one mutex under heavy throughput.
	thresh := e.uploadAlertBytes.Load()
	auto := e.autoBlock.Load()
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
