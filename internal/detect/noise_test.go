package detect

import (
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
	"net/netip"
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

// TunnelCrack LocalNet: the gateway treats all of RFC1918/CGNAT as LAN — direct
// egress AND inside the Permit set. A network claiming one of those ranges for a
// public service pulls traffic out of the tunnel and around the gate, so a
// "private" destination that is not on any real local subnet must be reported.
func TestLocalNetDestinationOutsideRealSubnetIsReported(t *testing.T) {
	e, _, got := newTestEngine(t)
	// The host really is on 192.168.31.0/24; everything else "private" is a claim.
	real, _ := netip.ParsePrefix("192.168.31.0/24")
	e.SetLocalNetCheck(func(a netip.Addr) bool { return real.Contains(a) })

	e.Track("tcp", "", "192.168.31.10:445", "127.0.0.1:1", "smbd", "", "direct")
	if n := countKind(*got, KindLocalNet); n != 0 {
		t.Fatalf("%d findings for a genuinely local destination", n)
	}

	// 100.64/10 is inside the LAN bypass but is not this host's subnet: exactly
	// what a hostile hotspot uses to look "local".
	e.Track("tcp", "", "100.64.7.9:443", "127.0.0.1:1", "curl", "", "direct")
	if n := countKind(*got, KindLocalNet); n == 0 {
		t.Fatal("a private-range destination outside every local subnet must be reported")
	}
}

// Without the on-link predicate the check must stay quiet rather than guess:
// alerting on every LAN print job would be worse than not looking.
func TestLocalNetSilentWithoutOnLinkKnowledge(t *testing.T) {
	e, _, got := newTestEngine(t)
	e.Track("tcp", "", "10.1.2.3:443", "127.0.0.1:1", "curl", "", "direct")
	if n := countKind(*got, KindLocalNet); n != 0 {
		t.Fatalf("%d findings with no local-subnet knowledge", n)
	}
}

// A client resolving through public DoH/DoT takes its names out of the gateway:
// query-level detection sees nothing and the Permit gate only sees an IP.
func TestEncryptedDNSBypassIsReported(t *testing.T) {
	e, _, got := newTestEngine(t)
	e.ApplyConfig(apitypes.DetectionConfig{BeaconEnabled: false, DGAEnabled: false, DNSBypassDetect: true})

	e.Track("tcp", "mozilla.cloudflare-dns.com", "104.16.249.249:443", "127.0.0.1:1", "firefox", "", "proxy")
	if n := countKind(*got, KindDNSBypass); n == 0 {
		t.Fatal("a client using public DoH must be reported")
	}

	// Ordinary HTTPS to the same provider's website is not DNS bypass...
	before := countKind(*got, KindDNSBypass)
	e.Track("tcp", "www.cloudflare.com", "104.16.132.229:443", "127.0.0.1:1", "firefox", "", "proxy")
	if countKind(*got, KindDNSBypass) != before {
		t.Fatal("a normal HTTPS connection must not be reported as DNS bypass")
	}
	// ...and neither is our own resolver doing its job.
	e.Track("tcp", "dns.google", "8.8.8.8:443", "127.0.0.1:1", "trust-proxy", "", "proxy")
	if countKind(*got, KindDNSBypass) != before {
		t.Fatal("the gateway's own resolver must not be flagged as bypassing itself")
	}
}

// Fingerprints are learned before they are reported: an unfamiliar hash from a
// cold start would fire on every browser update, which is how a detector becomes
// something people mute.
func TestFingerprintsAreLearnedBeforeReported(t *testing.T) {
	e, now, got := newTestEngine(t)
	e.ApplyConfig(apitypes.DetectionConfig{
		BeaconEnabled: false, DGAEnabled: false, JA4Enabled: true, JA4LearnMinutes: 60,
	})

	// During the window: observed, not reported.
	e.TrackWithFingerprint("tcp", "a.example", "1.2.3.4:443", "127.0.0.1:1", "chrome", "", "proxy", "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb")
	e.TrackWithFingerprint("tcp", "b.example", "1.2.3.4:443", "127.0.0.1:1", "curl", "", "proxy", "t13d1311h2_cccccccccccc_dddddddddddd")
	if n := countKind(*got, KindJA4); n != 0 {
		t.Fatalf("%d fingerprint alerts during the baseline window", n)
	}
	if learning, _ := e.FingerprintLearning(); !learning {
		t.Fatal("the window should still be open")
	}

	*now = now.Add(2 * time.Hour)

	// A stack already seen stays quiet...
	e.TrackWithFingerprint("tcp", "c.example", "1.2.3.4:443", "127.0.0.1:1", "chrome", "", "proxy", "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb")
	if n := countKind(*got, KindJA4); n != 0 {
		t.Fatalf("%d alerts for a fingerprint from the baseline", n)
	}
	// ...an unfamiliar one is reported once.
	e.TrackWithFingerprint("tcp", "evil.example", "5.6.7.8:443", "127.0.0.1:1", "weird-agent", "", "proxy", "t13i2109_eeeeeeeeeeee_ffffffffffff")
	if n := countKind(*got, KindJA4); n != 1 {
		t.Fatalf("%d alerts for a new stack after the window, want 1", n)
	}
	e.TrackWithFingerprint("tcp", "evil2.example", "5.6.7.8:443", "127.0.0.1:1", "weird-agent", "", "proxy", "t13i2109_eeeeeeeeeeee_ffffffffffff")
	if n := countKind(*got, KindJA4); n != 1 {
		t.Fatalf("%d alerts, want the same fingerprint reported only once", n)
	}

	rows := e.Fingerprints(10)
	if len(rows) != 3 {
		t.Fatalf("tracked %d fingerprints, want 3", len(rows))
	}
}

// Permitted destinations don't raise fingerprint alerts either — but the stack is
// still recorded, or the baseline would be missing exactly the traffic that is
// normal here.
func TestFingerprintsFromPermittedDestinationsAreRecordedNotAlerted(t *testing.T) {
	e, now, got := newTestEngine(t)
	e.SetTrustedDest(func(host, _ string) bool { return host == "api.anthropic.com" })
	e.ApplyConfig(apitypes.DetectionConfig{
		BeaconEnabled: false, DGAEnabled: false, JA4Enabled: true, JA4LearnMinutes: 1,
	})
	*now = now.Add(time.Hour) // window closed

	e.TrackWithFingerprint("tcp", "api.anthropic.com", "1.2.3.4:443", "127.0.0.1:1", "claude", "", "proxy", "t13d1516h2_111111111111_222222222222")
	if n := countKind(*got, KindJA4); n != 0 {
		t.Fatalf("%d alerts for a permitted destination", n)
	}
	if len(e.Fingerprints(10)) != 1 {
		t.Fatal("the stack must still be recorded so the baseline reflects normal traffic")
	}
}

// A client configured for public DoH keeps using it: on a real box one such
// client produced 614 connections to two endpoints in an hour. That is a
// standing condition, not 614 findings.
func TestDNSBypassIsReportedOncePerCooldown(t *testing.T) {
	e, now, got := newTestEngine(t)
	e.ApplyConfig(apitypes.DetectionConfig{
		BeaconEnabled: false, DGAEnabled: false,
		DNSBypassDetect: true, DNSBypassReAlertSec: 3600,
	})

	for i := 0; i < 200; i++ {
		e.Track("tcp", "cloudflare-dns.com", "104.16.249.249:443", "127.0.0.1:1", "warp", "", "proxy")
		*now = now.Add(10 * time.Second)
	}
	if n := countKind(*got, KindDNSBypass); n != 1 {
		t.Fatalf("%d findings for one client using one DoH endpoint over 33 minutes, want 1", n)
	}

	// A different endpoint is its own condition, and is reported.
	e.Track("tcp", "dns.quad9.net", "9.9.9.9:443", "127.0.0.1:1", "warp", "", "proxy")
	if n := countKind(*got, KindDNSBypass); n != 2 {
		t.Fatalf("%d findings, want the second endpoint reported too", n)
	}

	// Past the cooldown the first one is worth saying again.
	*now = now.Add(2 * time.Hour)
	e.Track("tcp", "cloudflare-dns.com", "104.16.249.249:443", "127.0.0.1:1", "warp", "", "proxy")
	if n := countKind(*got, KindDNSBypass); n != 3 {
		t.Fatalf("%d findings, want the condition re-reported after the cooldown", n)
	}
}

// Names under a hosting provider's suffix are generated by that provider's
// tooling, so their entropy says nothing. The only DGA finding on a real box was
// an AWS load balancer: daycount-1450237091.cn-north-1.elb.amazonaws.com.cn.
func TestHostedLabelsAreNotScoredAsDGA(t *testing.T) {
	e, _, got := newTestEngine(t)
	e.ApplyConfig(apitypes.DetectionConfig{BeaconEnabled: false, DGAEnabled: true})

	for _, host := range []string{
		"daycount-1450237091.cn-north-1.elb.amazonaws.com.cn",
		"a1b2c3d4e5f6g7h8.herokuapp.com",
		"x9y8z7w6v5u4t3s2.github.io",
	} {
		e.Track("tcp", host, "1.2.3.4:443", "127.0.0.1:1", "app", "", "proxy")
	}
	if n := countKind(*got, KindDGA); n != 0 {
		t.Fatalf("%d DGA findings for provider-generated hostnames", n)
	}

	// A real registration with the same shape is still scored — including the
	// kind of throwaway TLD a subscription link lives on.
	e.Track("tcp", "kq3v9z7x1p2m4w.com", "5.6.7.8:443", "127.0.0.1:1", "app", "", "proxy")
	if n := countKind(*got, KindDGA); n == 0 {
		t.Fatal("a high-entropy registered domain must still be scored")
	}
}
