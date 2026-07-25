package detect

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStore_QueryAndStats(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "detections.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	clk := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return clk }

	s.Record(Detection{Time: clk.Format(time.RFC3339), Kind: KindIntel, Host: "c2.evil", Action: ActionBanned, Reasons: []string{"intel"}})
	s.Record(Detection{Time: clk.Format(time.RFC3339), Kind: KindExfil, Host: "203.0.113.9", Action: ActionBanned, Reasons: []string{"upload"}})
	s.Record(Detection{Time: clk.Format(time.RFC3339), Kind: KindBeacon, Host: "same.host", Action: ActionAlert, Reasons: []string{"beaconing"}})
	s.Record(Detection{Time: clk.Add(-25 * time.Hour).Format(time.RFC3339), Kind: KindDGA, Host: "old.dga", Action: ActionAlert})

	page := s.Query(Query{Kind: KindIntel, Limit: 10})
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].Host != "c2.evil" {
		t.Fatalf("intel query: %+v", page)
	}
	page = s.Query(Query{Q: "beacon", Limit: 10})
	if page.Total != 1 || page.Items[0].Kind != KindBeacon {
		t.Fatalf("q=beacon: %+v", page)
	}
	st := s.Stats()
	if st.Alerts24h != 3 {
		t.Fatalf("alerts_24h=%d want 3", st.Alerts24h)
	}
	if st.Banned24h != 2 || st.Blocked24h != 2 {
		t.Fatalf("banned=%d blocked=%d", st.Banned24h, st.Blocked24h)
	}
	if st.ByKind["intel"] != 1 || st.ByKind["exfil"] != 1 || st.ByKind["beacon"] != 1 {
		t.Fatalf("by_kind=%v", st.ByKind)
	}

	// Reload from disk.
	s2, err := NewStore(filepath.Join(dir, "detections.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if s2.Query(Query{Limit: 100}).Total != 4 {
		t.Fatalf("reload total=%d", s2.Query(Query{Limit: 100}).Total)
	}
}

func TestTrack_EmitsDetectionKinds(t *testing.T) {
	e := New(100)
	e.SetAutoBlock(true)
	e.SetOnBan(func(domain, ip, reason string) {})
	var got []Detection
	e.SetOnDetection(func(d Detection) { got = append(got, d) })
	e.LoadThreats([]string{"malware.test"}, nil)

	ev := e.Track("tcp", "malware.test", "1.2.3.4:443", "src", "/bin/x", "", "direct")
	if !ev.Block {
		t.Fatal("expected Block")
	}
	if len(got) != 1 || got[0].Kind != KindIntel || got[0].Action != ActionBanned {
		t.Fatalf("intel detection: %+v", got)
	}
}

func TestExfil_EmitsBanned(t *testing.T) {
	e := New(100)
	e.SetAutoBlock(true)
	e.SetUploadAlert(100)
	e.SetOnBan(func(domain, ip, reason string) {})
	var got []Detection
	e.SetOnDetection(func(d Detection) { got = append(got, d) })

	ev := e.Track("tcp", "exfil.test", "9.9.9.9:443", "src", "python", "", "direct")
	if e.checkExfilMidStream(ev, 200) != true {
		t.Fatal("expected kill")
	}
	if len(got) != 1 || got[0].Kind != KindExfil || got[0].Action != ActionBanned {
		t.Fatalf("exfil: %+v", got)
	}
	// finalize must not double-emit
	e.finalize(ev)
	if len(got) != 1 {
		t.Fatalf("double emit: %d", len(got))
	}
}
