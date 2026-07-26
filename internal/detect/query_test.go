package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func queryEngine(t *testing.T) (*Engine, *time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	e := New(128)
	e.now = func() time.Time { return now }
	e.ApplyConfig(apitypes.DetectionConfig{
		BeaconEnabled: false, DGAEnabled: true,
		QueryWindowSec: 300, QueryNXBurst: 30, QueryParentRate: 300, QueryOddTypeAt: 20,
	})
	return e, &now
}

// The classic DGA signature: hundreds of generated names, nearly all NXDOMAIN,
// and only the one that resolves is ever dialled — so a connection tracker sees
// nothing at all.
func TestNXDomainSweepIsReported(t *testing.T) {
	e, now := queryEngine(t)
	var found []Detection
	for i := 0; i < 40; i++ {
		found = append(found, e.RecordQuery("192.168.1.50", fmt.Sprintf("kq%dv9z7x1p2m%d.com", i, i), "A", "NXDOMAIN")...)
		*now = now.Add(2 * time.Second)
	}
	if len(found) == 0 {
		t.Fatal("an NXDOMAIN sweep must be reported")
	}
	sweep := false
	for _, d := range found {
		for _, r := range d.Reasons {
			if strings.Contains(r, "DGA sweep") {
				sweep = true
			}
		}
	}
	if !sweep {
		t.Fatalf("no sweep finding among %d detections: %+v", len(found), found[0].Reasons)
	}
}

// Ordinary resolution — a handful of names, all NOERROR — must stay silent, or
// the detector is just noise with extra steps.
func TestOrdinaryResolutionIsSilent(t *testing.T) {
	e, now := queryEngine(t)
	for _, name := range []string{"github.com", "api.github.com", "www.google.com", "cdn.example.com"} {
		if d := e.RecordQuery("192.168.1.50", name, "A", "NOERROR"); len(d) != 0 {
			t.Fatalf("%s produced %d findings: %+v", name, len(d), d[0].Reasons)
		}
		*now = now.Add(time.Second)
	}
}

// A tunnel moves data as query names: high volume under one parent, and often
// payload-carrying record types.
func TestTunnelRateUnderOneParentIsReported(t *testing.T) {
	e, now := queryEngine(t)
	var found []Detection
	for i := 0; i < 320; i++ {
		found = append(found, e.RecordQuery("10.0.0.9", fmt.Sprintf("seg%04d.tunnel.example", i), "TXT", "NOERROR")...)
		*now = now.Add(time.Second)
	}
	if len(found) == 0 {
		t.Fatal("a high query rate under one parent must be reported")
	}
}

// Thresholds are configurable like every other detector; 0 disables the signal.
func TestQuerySignalsCanBeDisabled(t *testing.T) {
	e, now := queryEngine(t)
	e.ApplyConfig(apitypes.DetectionConfig{
		BeaconEnabled: false, DGAEnabled: false,
		QueryWindowSec: 300, QueryNXBurst: 0, QueryParentRate: 0, QueryOddTypeAt: 0,
	})
	for i := 0; i < 200; i++ {
		if d := e.RecordQuery("10.0.0.9", fmt.Sprintf("x%d.nx.example", i), "A", "NXDOMAIN"); len(d) != 0 {
			t.Fatalf("finding emitted with every query signal disabled: %+v", d[0].Reasons)
		}
		*now = now.Add(time.Second)
	}
}

// The stats feed the console: totals plus the busiest parents.
func TestQueryStats(t *testing.T) {
	e, now := queryEngine(t)
	for i := 0; i < 10; i++ {
		e.RecordQuery("10.0.0.1", fmt.Sprintf("a%d.busy.example", i), "A", "NOERROR")
		*now = now.Add(time.Second)
	}
	e.RecordQuery("10.0.0.1", "only.quiet.example", "A", "NXDOMAIN")
	st := e.QueryStats(5)
	if st.Total != 11 || st.NXDomain != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if len(st.TopParents) == 0 || st.TopParents[0].Parent != "busy.example" {
		t.Fatalf("top parents = %+v", st.TopParents)
	}
}

// Queries the gateway resolves for itself carry no client address (hijacked DNS
// on the box). Skipping those would blind the sweep detector exactly where a
// single-machine gateway needs it.
func TestSweepDetectedWithoutClientMetadata(t *testing.T) {
	e, now := queryEngine(t)
	var found []Detection
	for i := 0; i < 40; i++ {
		found = append(found, e.RecordQuery("", fmt.Sprintf("kq%dv9z7x1p2m%d.invalid", i, i), "A", "NXDOMAIN")...)
		*now = now.Add(time.Second)
	}
	sweep := false
	for _, d := range found {
		for _, r := range d.Reasons {
			if strings.Contains(r, "DGA sweep") {
				sweep = true
			}
		}
	}
	if !sweep {
		t.Fatal("a sweep with no client metadata must still be reported")
	}
}

// The per-parent NXDOMAIN column has to mean something: it drives the console's
// "which parent is failing to resolve" view.
func TestPerParentNXDomainIsCounted(t *testing.T) {
	e, now := queryEngine(t)
	for i := 0; i < 5; i++ {
		e.RecordQuery("10.0.0.2", fmt.Sprintf("a%d.flaky.example", i), "A", "NXDOMAIN")
		*now = now.Add(time.Second)
	}
	e.RecordQuery("10.0.0.2", "ok.flaky.example", "A", "NOERROR")
	for _, p := range e.QueryStats(5).TopParents {
		if p.Parent == "flaky.example" {
			if p.NXDomain != 5 || p.Queries != 6 {
				t.Fatalf("flaky.example = %+v, want 6 queries / 5 nxdomain", p)
			}
			return
		}
	}
	t.Fatal("flaky.example missing from the parent stats")
}
