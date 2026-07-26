package detect

import (
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countKind counts detections of one kind emitted through the sink.
func countKind(got []Detection, kind Kind) int {
	n := 0
	for _, d := range got {
		if d.Kind == kind {
			n++
		}
	}
	return n
}

// newTestEngine returns an engine with a controllable clock and a detection sink.
func newTestEngine(t *testing.T) (*Engine, *time.Time, *[]Detection) {
	t.Helper()
	now := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	var got []Detection
	e := New(256)
	e.now = func() time.Time { return now }
	e.SetOnDetection(func(d Detection) { got = append(got, d) })
	return e, &now, &got
}

// A 10-minute poller (VS Code update checks, a gas-price ticker, GCM push) used
// to re-alert every single cycle, because the cooldown equalled the cadence being
// reported: ~144 alerts a day, per host. The cooldown must outlast the interval
// it is describing.
func TestBeaconCooldownOutlastsTheCadence(t *testing.T) {
	e, now, got := newTestEngine(t)
	const period = 10 * time.Minute

	// A full day of a perfectly regular 10-minute poller.
	for i := 0; i < 144; i++ {
		e.Track("tcp", "poller.tp", "1.2.3.4:443", "127.0.0.1:1", "app", "", "direct")
		*now = now.Add(period)
	}

	alerts := countKind(*got, KindBeacon)
	if alerts == 0 {
		t.Fatal("a perfectly regular poller must still be reported at least once")
	}
	// 24h / (36 × 10min) = 4 windows, so a handful — not one per poll.
	if alerts > 6 {
		t.Fatalf("%d beacon alerts for one 10-minute poller in a day; the cooldown is not scaling with the cadence", alerts)
	}
}

// The cooldown scales with the observed interval, so a fast cadence is still
// reported promptly rather than being silenced for hours.
func TestBeaconFastCadenceStillReportedPromptly(t *testing.T) {
	e, now, got := newTestEngine(t)
	for i := 0; i < 60; i++ { // 30s cadence for 30 minutes
		e.Track("tcp", "fast.tp", "1.2.3.4:443", "127.0.0.1:1", "app", "", "direct")
		*now = now.Add(30 * time.Second)
	}
	if countKind(*got, KindBeacon) < 1 {
		t.Fatal("a 30s cadence must be reported")
	}
}

// A destination the operator explicitly Permitted is not an anomaly: a heartbeat
// to it is the approved behaviour. api.anthropic.com beaconing produced 24
// alerts/day on a real box purely because the Permit set was never consulted.
func TestPermittedDestinationsDoNotRaiseHeuristicAlerts(t *testing.T) {
	e, now, got := newTestEngine(t)
	e.SetTrustedDest(func(host, _ string) bool { return host == "api.anthropic.com" })

	for i := 0; i < 40; i++ {
		e.Track("tcp", "api.anthropic.com", "1.2.3.4:443", "127.0.0.1:1", "claude", "", "proxy")
		*now = now.Add(time.Minute)
	}
	if n := countKind(*got, KindBeacon); n != 0 {
		t.Fatalf("%d beacon alerts for an explicitly permitted destination", n)
	}

	// Same cadence, unlisted destination => still reported. Without this the
	// change would just be "turn the detector off".
	for i := 0; i < 40; i++ {
		e.Track("tcp", "unknown-c2.tp", "5.6.7.8:443", "127.0.0.1:1", "app", "", "proxy")
		*now = now.Add(time.Minute)
	}
	if n := countKind(*got, KindBeacon); n == 0 {
		t.Fatal("an unlisted destination with the same cadence must still be reported")
	}
}

// DGA scoring flagged rr4---sn-3pm7dn7d.googlevideo.com every time YouTube
// picked a CDN host. Permitted parents are exempt; unlisted ones are not.
func TestPermittedDomainsSkipDGAScoring(t *testing.T) {
	e, _, got := newTestEngine(t)
	e.SetTrustedDest(func(host, _ string) bool { return strings.HasSuffix(host, "googlevideo.com") })

	e.Track("tcp", "rr4---sn-3pm7dn7d.googlevideo.com", "1.2.3.4:443", "127.0.0.1:1", "chrome", "", "proxy")
	if n := countKind(*got, KindDGA); n != 0 {
		t.Fatalf("%d DGA alerts for a permitted CDN host", n)
	}

	e.Track("tcp", "kq3v9z7x1p2m4w.com", "5.6.7.8:443", "127.0.0.1:1", "app", "", "proxy")
	if n := countKind(*got, KindDGA); n == 0 {
		t.Fatal("an unlisted high-entropy domain must still be scored")
	}
}

// Trust silences heuristics, never threat intel: a permitted domain showing up
// on a feed is exactly the case that must still shout.
func TestThreatIntelStillFiresForPermittedDestinations(t *testing.T) {
	e, _, got := newTestEngine(t)
	e.SetTrustedDest(func(string, string) bool { return true })
	e.SetFeedThreats([]string{"evil.tp"}, nil)

	e.Track("tcp", "evil.tp", "9.9.9.9:443", "127.0.0.1:1", "app", "", "proxy")
	if n := countKind(*got, KindIntel); n == 0 {
		t.Fatal("threat-intel hits must not be suppressed by the Permit set")
	}
}

// A byte threshold alone says "someone uploaded a lot" — a photo sync, a
// container push, an AI coding agent. Exfil is the *shape*: lopsided, or bound
// somewhere never seen before.
func TestExfilNeedsShapeNotJustBytes(t *testing.T) {
	e, now, got := newTestEngine(t)
	cfg := apitypes.DetectionConfig{
		BeaconEnabled: false, DGAEnabled: false, AutoBlock: false,
		ExfilUploadBytes: 1 << 20, ExfilMinRatio: 4, ExfilNewDestHours: 1,
	}
	e.ApplyConfig(cfg)

	// Establish the destination as long-known, then upload a lot with plenty
	// coming back: a sync, not an exfil.
	ev := e.Track("tcp", "backup.known.tp", "1.2.3.4:443", "127.0.0.1:1", "app", "", "direct")
	*now = now.Add(3 * time.Hour)
	atomic.StoreInt64(&ev.Upload, 50<<20)
	atomic.StoreInt64(&ev.Download, 40<<20)
	e.finalize(ev)
	if n := countKind(*got, KindExfil); n != 0 {
		t.Fatalf("%d exfil alerts for balanced traffic to a known destination", n)
	}

	// Same volume, nothing coming back => lopsided.
	ev2 := e.Track("tcp", "backup.known.tp", "1.2.3.4:443", "127.0.0.1:1", "app", "", "direct")
	atomic.StoreInt64(&ev2.Upload, 50<<20)
	atomic.StoreInt64(&ev2.Download, 1<<10)
	e.finalize(ev2)
	if n := countKind(*got, KindExfil); n == 0 {
		t.Fatal("a lopsided upload must still alert")
	}

	// A first-seen destination is interesting even when the ratio is mild.
	before := countKind(*got, KindExfil)
	ev3 := e.Track("tcp", "brand-new.tp", "9.9.9.9:443", "127.0.0.1:1", "app", "", "direct")
	atomic.StoreInt64(&ev3.Upload, 50<<20)
	atomic.StoreInt64(&ev3.Download, 30<<20)
	e.finalize(ev3)
	if countKind(*got, KindExfil) == before {
		t.Fatal("a large upload to a never-seen destination must alert")
	}
}

// Disposal must not run while the Permit index is still being built: every
// rule-set-derived Permit reads as "not permitted" until it lands, so a large
// upload in that window would ban a destination the operator had approved.
// Alerting is unaffected.
func TestDisposalWaitsForTheWarmPermitIndex(t *testing.T) {
	e, _, got := newTestEngine(t)
	var banned []string
	e.SetOnBan(func(domain, ip, reason string) { banned = append(banned, domain+ip) })
	warm := false
	e.SetDisposalReady(func() bool { return warm })
	e.ApplyConfig(apitypes.DetectionConfig{
		BeaconEnabled: false, DGAEnabled: false, AutoBlock: true,
		ExfilUploadBytes: 1 << 20,
	})

	ev := e.Track("tcp", "unknown.tp", "5.5.5.5:443", "127.0.0.1:1", "app", "", "proxy")
	atomic.StoreInt64(&ev.Upload, 20<<20)
	e.finalize(ev)
	if len(banned) != 0 {
		t.Fatalf("banned %v before the permit index was warm", banned)
	}
	if countKind(*got, KindExfil) == 0 {
		t.Fatal("the finding must still be reported while disposal waits")
	}

	warm = true
	ev2 := e.Track("tcp", "unknown2.tp", "6.6.6.6:443", "127.0.0.1:1", "app", "", "proxy")
	atomic.StoreInt64(&ev2.Upload, 20<<20)
	e.finalize(ev2)
	if len(banned) == 0 {
		t.Fatal("disposal must resume once the permit index is warm")
	}
}

// Thresholds are operator-tunable at runtime, not baked in.
func TestApplyConfigChangesThresholds(t *testing.T) {
	e, now, got := newTestEngine(t)
	e.ApplyConfig(apitypes.DetectionConfig{BeaconEnabled: false, DGAEnabled: true})
	for i := 0; i < 40; i++ {
		e.Track("tcp", "poller.tp", "1.2.3.4:443", "127.0.0.1:1", "app", "", "direct")
		*now = now.Add(time.Minute)
	}
	if n := countKind(*got, KindBeacon); n != 0 {
		t.Fatalf("%d beacon alerts after disabling the detector", n)
	}

	// Re-enable with a tight window and it reports again.
	e.ApplyConfig(apitypes.DetectionConfig{BeaconEnabled: true, DGAEnabled: true, BeaconMinSample: 4})
	for i := 0; i < 40; i++ {
		e.Track("tcp", "poller2.tp", "1.2.3.4:443", "127.0.0.1:1", "app", "", "direct")
		*now = now.Add(time.Minute)
	}
	if n := countKind(*got, KindBeacon); n == 0 {
		t.Fatal("beacon detection must come back when re-enabled")
	}
}
