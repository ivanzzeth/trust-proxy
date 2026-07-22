package detect

import (
	"strings"
	"testing"
	"time"
)

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
