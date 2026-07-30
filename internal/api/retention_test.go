package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/retentioncfg"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// errTestApply is the failure every applier fake reports; the handlers only care
// that something went wrong, never what.
var errTestApply = errors.New("applier said no")

type fakeRetention struct {
	applied  []apitypes.Retention
	failWith error
}

func (f *fakeRetention) SetRetention(r apitypes.Retention) error {
	if f.failWith != nil {
		return f.failWith
	}
	f.applied = append(f.applied, r)
	return nil
}

func newRetentionServer(t *testing.T) (*Server, *retentioncfg.Store, *fakeRetention) {
	t.Helper()
	store, err := retentioncfg.NewStore(filepath.Join(t.TempDir(), "retention.json"))
	if err != nil {
		t.Fatal(err)
	}
	app := &fakeRetention{}
	return &Server{retention: store, retApplier: app}, store, app
}

func putRetention(t *testing.T, s *Server, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	rr := httptest.NewRecorder()
	s.handleSetRetention(rr, httptest.NewRequest(http.MethodPut, "/api/retention", bytes.NewReader(b)))
	return rr
}

func TestRetentionHandlers(t *testing.T) {
	s, store, app := newRetentionServer(t)

	rr := httptest.NewRecorder()
	s.handleGetRetention(rr, httptest.NewRequest(http.MethodGet, "/api/retention", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status %d", rr.Code)
	}
	var got apitypes.Retention
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got != (apitypes.Retention{}) {
		t.Fatalf("a fresh store must have no opinion, got %+v", got)
	}

	on := true
	want := apitypes.Retention{
		Log:     apitypes.RetentionRule{MaxSizeMB: 8, MaxBackups: 5, Compress: &on},
		History: apitypes.RetentionRule{MaxSizeMB: 64, MaxBackups: 2},
	}
	if rr := putRetention(t, s, want); rr.Code != http.StatusOK {
		t.Fatalf("PUT status %d body %s", rr.Code, rr.Body.String())
	}
	if store.Get().Log.MaxSizeMB != 8 || store.Get().History.MaxSizeMB != 64 {
		t.Fatalf("store after PUT: %+v", store.Get())
	}
	if len(app.applied) != 1 {
		t.Fatalf("applier saw %+v", app.applied)
	}

	// Turning history rotation off makes boot time grow without limit (startup
	// replays the live file), so the store refuses it.
	bad := apitypes.Retention{History: apitypes.RetentionRule{MaxSizeMB: retentioncfg.NoRotation}}
	if rr := putRetention(t, s, bad); rr.Code != http.StatusBadRequest {
		t.Fatalf("history no-rotation status %d want 400", rr.Code)
	}
	if store.Get().Log.MaxSizeMB != 8 {
		t.Fatalf("refused PUT changed the store: %+v", store.Get())
	}
}

func TestRetentionApplyFailureRollsBackTheStore(t *testing.T) {
	s, store, app := newRetentionServer(t)
	if rr := putRetention(t, s, apitypes.Retention{
		Log: apitypes.RetentionRule{MaxSizeMB: 8},
	}); rr.Code != http.StatusOK {
		t.Fatalf("seed PUT: %d %s", rr.Code, rr.Body.String())
	}

	app.failWith = errTestApply
	rr := putRetention(t, s, apitypes.Retention{Log: apitypes.RetentionRule{MaxSizeMB: 99}})
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("failed apply status %d want 502", rr.Code)
	}
	if store.Get().Log.MaxSizeMB != 8 {
		t.Fatalf("store after failed apply: %+v, want the previous value", store.Get())
	}
}

// TestCompressIsTriStateOnTheWire pins the reason RetentionRule.Compress is a
// pointer: the default is on, a plain bool's zero value is off, so a client
// sending only max_size_mb would silently disable gzip — a setting nobody
// touched changing itself.
func TestCompressIsTriStateOnTheWire(t *testing.T) {
	var r apitypes.RetentionRule
	if err := json.Unmarshal([]byte(`{"max_size_mb":8}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Compress != nil {
		t.Fatalf("an absent compress must stay unset, got %v", *r.Compress)
	}
	if !r.CompressOr(true) {
		t.Fatal("unset compress must resolve to the caller's default")
	}
	if err := json.Unmarshal([]byte(`{"compress":false}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Compress == nil || r.CompressOr(true) {
		t.Fatal("an explicit false must survive")
	}
}

// TestDefaultsAreReadFromTheOwningPackages guards the endpoint's whole purpose:
// it must report what the gateway would actually do, not numbers restated here.
func TestDefaultsAreReadFromTheOwningPackages(t *testing.T) {
	rr := httptest.NewRecorder()
	(&Server{}).handleDefaults(rr, httptest.NewRequest(http.MethodGet, "/api/defaults", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	var d apitypes.Defaults
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Inbound.Listen != apitypes.DefaultInboundListen || d.Inbound.Port != apitypes.DefaultInboundPort {
		t.Fatalf("inbound defaults: %+v", d.Inbound)
	}
	// Every block must be populated: an empty one means a domain quietly fell out
	// of the aggregation and the console starts rendering blanks as "0".
	if d.Retention.Log.MaxSizeMB == 0 || d.Retention.History.MaxSizeMB == 0 {
		t.Fatalf("retention defaults: %+v", d.Retention)
	}
	if d.Failover.ProbeIntervalSeconds == 0 || d.Scoring.MinSamples == 0 {
		t.Fatalf("failover/scoring defaults: %+v %+v", d.Failover, d.Scoring)
	}
	if d.TUN.Stack == "" || d.Detection.BeaconMinSample == 0 {
		t.Fatalf("tun/detection defaults: %+v %+v", d.TUN, d.Detection)
	}
}
