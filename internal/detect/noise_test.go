package detect

import (
	"strings"
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
