package proxygroups

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The defaults decide whether a login survives a re-election, so assert them
// explicitly rather than reading them back from whatever was persisted.
func TestFailoverDefaults(t *testing.T) {
	var f Failover
	if f.Interval() != DefaultProbeInterval || f.Tolerance() != DefaultProbeTolerance || f.IdleTimeout() != DefaultIdleTimeout {
		t.Fatalf("zero Failover = %ds/%dms/%ds, want %d/%d/%d",
			f.Interval(), f.Tolerance(), f.IdleTimeout(),
			DefaultProbeInterval, DefaultProbeTolerance, DefaultIdleTimeout)
	}
	if f.InterruptExistingConnections {
		t.Fatal("interruption must default OFF: it kills live connections on re-election")
	}
	if DefaultProbeTolerance <= 50 {
		t.Fatalf("tolerance %d is at or under sing-box's own 50ms default — that is the jitter range that caused the churn", DefaultProbeTolerance)
	}
}

func TestFailoverValidation(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "pg.json"))
	if err != nil {
		t.Fatal(err)
	}
	bad := []Failover{
		{ProbeIntervalSeconds: -1},
		{ProbeIntervalSeconds: 3},                           // pointless churn
		{ToleranceMS: 60001},                                // never switches
		{ProbeIntervalSeconds: 600, IdleTimeoutSeconds: 60}, // sing-box rejects interval > idle_timeout
	}
	for _, f := range bad {
		if _, err := s.Set(Config{Failover: f}); err == nil {
			t.Fatalf("Set accepted invalid failover %+v", f)
		}
	}
	if got := s.Get().Failover; got != (Failover{}) {
		t.Fatalf("a rejected Set must not mutate the store, got %+v", got)
	}
	good := Failover{ProbeIntervalSeconds: 60, ToleranceMS: 500, IdleTimeoutSeconds: 3600, InterruptExistingConnections: true}
	if _, err := s.Set(Config{Failover: good}); err != nil {
		t.Fatalf("Set rejected a valid failover: %v", err)
	}
	if got := s.Get().Failover; got != good {
		t.Fatalf("failover round-trip = %+v, want %+v", got, good)
	}
}

// A hand-edited or downgraded file must not brick the gateway: bad values fall
// back to the safe defaults instead of failing the load.
func TestFailoverSanitizesOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pg.json")
	raw := `{"auto_country":true,"exclude_countries":["HK"],"groups":[],"failover":{"probe_interval_seconds":1,"tolerance_ms":-5}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("a bad failover block must not fail the load: %v", err)
	}
	if got := s.Get().Failover; got != (Failover{}) {
		t.Fatalf("bad failover should reset to defaults, got %+v", got)
	}
	var on disk
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &on); err != nil {
		t.Fatal(err)
	}
	if on.Failover.ProbeIntervalSeconds != 0 {
		t.Fatalf("sanitized config should have been persisted, file still has %+v", on.Failover)
	}
}

type disk struct {
	Failover Failover `json:"failover"`
}
