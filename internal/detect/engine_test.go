package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestDGAandTunnel(t *testing.T) {
	e := New(4000)
	clk := time.Unix(1_700_000_000, 0)
	e.now = func() time.Time { return clk }
	has := func(ev *Event, sub string) bool {
		for _, r := range ev.Reasons {
			if strings.Contains(r, sub) {
				return true
			}
		}
		return false
	}
	track := func(host string) *Event { return e.Track("tcp", host, "1.2.3.4:443", "s", "", "", "direct") }

	// Legitimate domains must NOT be flagged.
	for _, d := range []string{"wikipedia.org", "google.com", "api.ipify.org", "example.com", "d1a2b3c4.cloudfront.net"} {
		ev := track(d)
		if has(ev, "DGA") || has(ev, "DNS tunnel") || has(ev, "tunneling") {
			t.Fatalf("false positive on %s: %v", d, ev.Reasons)
		}
	}
	// DGA-like registrable label.
	if ev := track("kq3v9z7x1p2m4r8t.com"); !has(ev, "DGA-like") {
		t.Fatalf("DGA not flagged: %v", ev.Reasons)
	}
	// Long high-entropy subdomain label (data encoding).
	if ev := track("mz2k9qw7rt4xy1bv6nc3ld8pf0ah5.tun.evil.io"); !has(ev, "DNS tunnel") {
		t.Fatalf("tunnel label not flagged: %v", ev.Reasons)
	}
	// Volume: many distinct subdomains under one parent.
	for i := 0; i < 45; i++ {
		track(fmt.Sprintf("h%d.flux.example", i))
	}
	found := false
	for _, ev := range e.Events() {
		if has(&ev, "distinct subdomains") {
			found = true
		}
	}
	if !found {
		t.Fatal("volume tunneling/fast-flux not flagged")
	}
}

func TestBeaconing(t *testing.T) {
	e := New(100)
	clk := time.Unix(1_700_000_000, 0)
	e.now = func() time.Time { return clk }

	// 6 regular connections (every 30s) to the same dest => C2 heartbeat.
	var last *Event
	for i := 0; i < 6; i++ {
		last = e.Track("tcp", "c2.beacon.test", "1.2.3.4:443", "src", "", "", "direct")
		clk = clk.Add(30 * time.Second)
	}
	if last.Level != "alert" {
		t.Fatalf("expected beaconing alert, got level=%q reasons=%v", last.Level, last.Reasons)
	}
	found := false
	for _, r := range last.Reasons {
		if strings.Contains(r, "beaconing") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no beaconing reason: %v", last.Reasons)
	}
	// Heuristic => must NOT be auto-block eligible.
	if last.Block {
		t.Fatal("beaconing must not set Block")
	}

	// Irregular cadence must NOT beacon.
	e2 := New(100)
	c2 := time.Unix(1_700_000_000, 0)
	e2.now = func() time.Time { return c2 }
	jitter := []time.Duration{3, 47, 8, 90, 5, 61, 2} // wildly variable
	var lastJ *Event
	for _, d := range jitter {
		lastJ = e2.Track("tcp", "noisy.test", "5.6.7.8:443", "src", "", "", "direct")
		c2 = c2.Add(d * time.Second)
	}
	for _, r := range lastJ.Reasons {
		if strings.Contains(r, "beaconing") {
			t.Fatalf("irregular traffic wrongly flagged as beaconing: %v", lastJ.Reasons)
		}
	}
}

func TestThreatMatch_StaticAndFeed(t *testing.T) {
	e := New(100)
	e.LoadThreats([]string{"malware.test"}, []string{"1.2.3.4"})
	e.SetFeedThreats([]string{"c2.feed.example"}, []string{"9.9.9.9"})

	cases := []struct {
		name       string
		host, dst  string
		wantAlert  bool
		wantReason string
	}{
		{"static domain", "malware.test", "5.6.7.8:443", true, "threat-intel domain match: malware.test"},
		{"feed domain", "c2.feed.example", "5.6.7.8:443", true, "threat-intel domain match: c2.feed.example"},
		{"static ip", "", "1.2.3.4:443", true, "threat-intel IP match: 1.2.3.4"},
		{"feed ip", "", "9.9.9.9:443", true, "threat-intel IP match: 9.9.9.9"},
		{"clean domain", "example.org", "5.6.7.8:443", false, ""},
		{"case-insensitive", "MALWARE.test", "5.6.7.8:443", true, "threat-intel domain match: MALWARE.test"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := e.Track("tcp", c.host, c.dst, "127.0.0.1:1", "", "(rule)", "direct")
			gotAlert := ev.Level == "alert"
			if gotAlert != c.wantAlert {
				t.Fatalf("level=%q wantAlert=%v", ev.Level, c.wantAlert)
			}
			if c.wantReason != "" {
				found := false
				for _, r := range ev.Reasons {
					if r == c.wantReason {
						found = true
					}
				}
				if !found {
					t.Fatalf("reasons=%v want %q", ev.Reasons, c.wantReason)
				}
			}
		})
	}
}

func TestSetFeedThreats_Replaces(t *testing.T) {
	e := New(100)
	e.SetFeedThreats([]string{"a.example"}, nil)
	if ev := e.Track("tcp", "a.example", "1.1.1.1:1", "x", "", "", ""); ev.Level != "alert" {
		t.Fatal("a.example should alert after first feed load")
	}
	// A refresh with a different set must drop the stale indicator.
	e.SetFeedThreats([]string{"b.example"}, nil)
	if ev := e.Track("tcp", "a.example", "1.1.1.1:1", "x", "", "", ""); ev.Level == "alert" {
		t.Fatal("a.example must no longer alert after feed replace")
	}
	if ev := e.Track("tcp", "b.example", "1.1.1.1:1", "x", "", "", ""); ev.Level != "alert" {
		t.Fatal("b.example should alert after feed replace")
	}
}

func TestLargeUploadAlert(t *testing.T) {
	e := New(100)
	e.SetUploadAlert(1024)
	ev := e.Track("tcp", "ok.example", "1.1.1.1:443", "x", "", "", "direct")
	if ev.Level == "alert" {
		t.Fatal("should not alert before upload")
	}
	ev.Upload = 2048
	e.finalize(ev)
	if ev.Level != "alert" {
		t.Fatalf("should alert on large upload, got %q reasons=%v", ev.Level, ev.Reasons)
	}
	if ev.Block {
		t.Fatal("without auto-block, large upload must not set Block")
	}
}

func TestLargeUpload_PackPermitIsTrusted(t *testing.T) {
	// Regression: Allow packs open L3 via customrules.Permit, but trustedDest
	// used to only check whitelist.json — Cursor Agent uploads then got
	// auto-banned (e.g. agentn.global.api5.cursor.sh).
	e := New(100)
	e.SetUploadAlert(1024)
	e.SetAutoBlock(true)
	var cursor []apitypes.CustomRule
	for _, p := range customrules.Presets {
		if p.Name == "Cursor" {
			cursor = p.Rules
			break
		}
	}
	if len(cursor) == 0 {
		t.Fatal("Cursor preset missing")
	}
	rules := customrules.Rules{Rules: cursor}
	e.SetTrustedDest(func(host, dest string) bool {
		return customrules.MatchesPermit(rules, host, dest)
	})
	banned := false
	e.SetOnBan(func(domain, ip, reason string) { banned = true })

	ev := e.Track("tcp", "agentn.global.api5.cursor.sh", "1.2.3.4:443", "x", "Cursor", "", "proxy/proxy")
	ev.Upload = 50 << 20
	e.finalize(ev)
	if ev.Level != "alert" {
		t.Fatal("large upload still alerts")
	}
	if ev.Block || banned {
		t.Fatalf("Cursor pack host must not auto-ban: block=%v banned=%v", ev.Block, banned)
	}
}

func TestLargeUpload_NonWhitelistAutoBan(t *testing.T) {
	e := New(100)
	e.SetUploadAlert(1024)
	e.SetAutoBlock(true)
	e.SetTrustedDest(func(host, dest string) bool { return host == "trusted.example" })
	var bannedDomain, bannedIP, bannedReason string
	e.SetOnBan(func(domain, ip, reason string) {
		bannedDomain, bannedIP, bannedReason = domain, ip, reason
	})

	ev := e.Track("tcp", "evil.example", "9.9.9.9:443", "x", "", "", "proxy/proxy")
	ev.Upload = 2048
	e.finalize(ev)
	if !ev.Block {
		t.Fatal("non-whitelist large upload must Block when auto-block on")
	}
	if bannedDomain != "evil.example" || bannedIP != "9.9.9.9" {
		t.Fatalf("ban sink got domain=%q ip=%q", bannedDomain, bannedIP)
	}
	if bannedReason == "" {
		t.Fatal("expected ban reason")
	}

	// Whitelisted destination: alert only.
	bannedDomain, bannedIP = "", ""
	ev2 := e.Track("tcp", "trusted.example", "8.8.8.8:443", "x", "", "", "proxy/proxy")
	ev2.Upload = 4096
	e.finalize(ev2)
	if ev2.Level != "alert" {
		t.Fatal("whitelist large upload still alerts")
	}
	if ev2.Block {
		t.Fatal("whitelist large upload must not Block")
	}
	if bannedDomain != "" || bannedIP != "" {
		t.Fatal("whitelist upload must not ban")
	}
}

func TestLargeUpload_MidStreamKill(t *testing.T) {
	e := New(100)
	e.SetUploadAlert(100)
	e.SetAutoBlock(true)
	e.SetTrustedDest(func(host, dest string) bool { return false })
	banned := false
	e.SetOnBan(func(domain, ip, reason string) { banned = true })

	ev := e.Track("tcp", "exfil.example", "1.2.3.4:443", "x", "", "", "proxy/proxy")
	if !e.checkExfilMidStream(ev, 50) {
		// under threshold
	} else {
		t.Fatal("under threshold must not kill")
	}
	if !e.checkExfilMidStream(ev, 200) {
		t.Fatal("over threshold must kill")
	}
	if !ev.Block || !banned {
		t.Fatalf("block=%v banned=%v", ev.Block, banned)
	}
	// Second call: already Block, no re-kill needed
	if e.checkExfilMidStream(ev, 300) {
		t.Fatal("already blocked must not re-trigger kill")
	}
}

func TestThreatIntel_BanFromEvent(t *testing.T) {
	e := New(100)
	e.LoadThreats([]string{"malware.test"}, nil)
	var got string
	e.SetOnBan(func(domain, ip, reason string) { got = domain })
	ev := e.Track("tcp", "malware.test", "5.6.7.8:443", "x", "", "", "direct")
	if !ev.Block {
		t.Fatal("expected Block")
	}
	e.BanFromEvent(ev, "threat-intel auto-block")
	if got != "malware.test" {
		t.Fatalf("ban domain=%q", got)
	}
}

func TestRestoreEvents_RoundTrip(t *testing.T) {
	e := New(100)
	e.Track("tcp", "a.example", "1.1.1.1:1", "x", "", "", "")
	e.Track("tcp", "b.example", "2.2.2.2:2", "y", "", "", "")
	snap := e.Events() // newest-first

	e2 := New(100)
	e2.RestoreEvents(snap)
	got := e2.Events()
	if len(got) != 2 {
		t.Fatalf("restored %d events, want 2", len(got))
	}
	if got[0].Host != "b.example" || got[1].Host != "a.example" {
		t.Fatalf("order wrong after restore: %q %q", got[0].Host, got[1].Host)
	}
	// A new event must get an ID above the restored max.
	ev := e2.Track("tcp", "c.example", "3.3.3.3:3", "z", "", "", "")
	if ev.ID <= snap[0].ID {
		t.Fatalf("new id %d not above restored max %d", ev.ID, snap[0].ID)
	}
}
