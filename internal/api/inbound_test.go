package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/inboundcfg"
	"github.com/ivanzzeth/trust-proxy/internal/users"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// fakeInbound stands in for gateway.Manager: it records what the handler asked
// for and can be told to fail, which is the only way to exercise the rollback.
type fakeInbound struct {
	cur       apitypes.InboundListen
	applied   []apitypes.InboundListen
	failWith  error
	confirmed int
	pendingTo apitypes.InboundListen
	pendingOK bool
}

func (f *fakeInbound) InboundListen() apitypes.InboundListen { return f.cur }

func (f *fakeInbound) SetInboundListen(l apitypes.InboundListen) error {
	if f.failWith != nil {
		return f.failWith
	}
	f.applied = append(f.applied, l)
	f.cur = l
	return nil
}

func (f *fakeInbound) SetInboundListenGuarded(l apitypes.InboundListen, _ time.Duration) (apitypes.InboundListen, error) {
	if f.failWith != nil {
		return f.cur, f.failWith
	}
	prev := f.cur
	f.applied = append(f.applied, l)
	f.cur = l
	f.pendingTo, f.pendingOK = prev, true
	return prev, nil
}

func (f *fakeInbound) ConfirmInboundListen() { f.confirmed++; f.pendingOK = false }

func (f *fakeInbound) PendingInboundRevert() (apitypes.InboundListen, int, bool) {
	return f.pendingTo, 42, f.pendingOK
}

func newInboundServer(t *testing.T) (*Server, *inboundcfg.Store, *fakeInbound, *users.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := inboundcfg.NewStore(filepath.Join(dir, "inbound.json"))
	if err != nil {
		t.Fatal(err)
	}
	us, err := users.NewStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	app := &fakeInbound{}
	return &Server{inbListen: store, inbListenApplier: app, users: us}, store, app, us
}

func putInbound(t *testing.T, s *Server, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	rr := httptest.NewRecorder()
	s.handleSetInbound(rr, httptest.NewRequest(http.MethodPut, "/api/inbound", bytes.NewReader(b)))
	return rr
}

func TestInboundHandlers(t *testing.T) {
	s, store, app, _ := newInboundServer(t)

	rr := httptest.NewRecorder()
	s.handleGetInbound(rr, httptest.NewRequest(http.MethodGet, "/api/inbound", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status %d", rr.Code)
	}
	var got apitypes.InboundListenState
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Listen != (apitypes.InboundListen{}) {
		t.Fatalf("a fresh store must have no opinion, got %+v", got.Listen)
	}
	if got.Resolved.Listen != apitypes.DefaultInboundListen || got.Resolved.Port != apitypes.DefaultInboundPort {
		t.Fatalf("resolved defaults wrong: %+v", got.Resolved)
	}

	if rr := putInbound(t, s, map[string]any{"listen": "127.0.0.1", "port": 31584}); rr.Code != http.StatusOK {
		t.Fatalf("PUT status %d body %s", rr.Code, rr.Body.String())
	}
	if store.Get().Port != 31584 {
		t.Fatalf("store after PUT: %+v", store.Get())
	}
	if len(app.applied) != 1 || app.applied[0].Port != 31584 {
		t.Fatalf("applier saw %+v", app.applied)
	}

	// Colliding with the API port is the mistake that locks an operator out of
	// the console, so it has to be refused rather than merely fail at rebuild.
	if rr := putInbound(t, s, map[string]any{"listen": "127.0.0.1", "port": 21585}); rr.Code != http.StatusBadRequest {
		t.Fatalf("api-port collision status %d want 400", rr.Code)
	}
	if store.Get().Port != 31584 {
		t.Fatalf("refused PUT changed the store: %+v", store.Get())
	}
}

func TestInboundApplyFailureRollsBackTheStore(t *testing.T) {
	s, store, app, _ := newInboundServer(t)
	if rr := putInbound(t, s, map[string]any{"listen": "127.0.0.1", "port": 31584}); rr.Code != http.StatusOK {
		t.Fatalf("seed PUT: %d %s", rr.Code, rr.Body.String())
	}

	app.failWith = errTestApply
	rr := putInbound(t, s, map[string]any{"listen": "127.0.0.1", "port": 31599})
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("failed apply status %d want 502", rr.Code)
	}
	// The store is what the next rebuild reads. Leaving the rejected value in it
	// would make a change that visibly failed take effect at the next restart.
	if store.Get().Port != 31584 {
		t.Fatalf("store after failed apply: %+v, want the previous value", store.Get())
	}
}

func TestInboundGuardedPutReportsThePendingRevert(t *testing.T) {
	s, _, app, _ := newInboundServer(t)
	rr := putInbound(t, s, map[string]any{"listen": "127.0.0.1", "port": 31584, "guard_seconds": 60})
	if rr.Code != http.StatusOK {
		t.Fatalf("guarded PUT: %d %s", rr.Code, rr.Body.String())
	}
	var resp apitypes.InboundListenState
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Revert == nil {
		t.Fatalf("guarded PUT must report the countdown: %s", rr.Body.String())
	}

	// A browser that reloaded mid-countdown learns about it only from the GET.
	rr = httptest.NewRecorder()
	s.handleGetInbound(rr, httptest.NewRequest(http.MethodGet, "/api/inbound", nil))
	var g apitypes.InboundListenState
	_ = json.Unmarshal(rr.Body.Bytes(), &g)
	if g.Revert == nil {
		t.Fatalf("GET must surface a pending revert: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.handleConfirmInbound(rr, httptest.NewRequest(http.MethodPost, "/api/inbound/confirm", nil))
	if rr.Code != http.StatusOK || app.confirmed != 1 {
		t.Fatalf("confirm status %d confirmed=%d", rr.Code, app.confirmed)
	}
}

// TestInboundRefusesAnonymousExposure is the teeth of the check that keeps a
// bind off loopback from turning the machine into an open relay. The failure it
// guards is silent in the worst direction: the rebuild succeeds and every
// screen looks right.
func TestInboundRefusesAnonymousExposure(t *testing.T) {
	s, store, app, us := newInboundServer(t)

	rr := putInbound(t, s, map[string]any{"listen": "0.0.0.0", "port": 21584})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("off-loopback bind with no proxy password: status %d want 400", rr.Code)
	}
	// Not written, not applied — a refused request must leave no trace, or the
	// bind lands at the next restart with nobody having approved it.
	if store.Get() != (apitypes.InboundListen{}) {
		t.Fatalf("refused bind was persisted: %+v", store.Get())
	}
	if len(app.applied) != 0 {
		t.Fatalf("refused bind was applied: %+v", app.applied)
	}

	u, err := us.Create("alice", "correct-horse-battery", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := us.SetProxyPassword(u.ID, "s3cret-enough"); err != nil {
		t.Fatal(err)
	}
	if rr := putInbound(t, s, map[string]any{"listen": "0.0.0.0", "port": 21584}); rr.Code != http.StatusOK {
		t.Fatalf("with a proxy password the same bind must succeed: %d %s", rr.Code, rr.Body.String())
	}
	if store.Get().Listen != "0.0.0.0" {
		t.Fatalf("store after allowed bind: %+v", store.Get())
	}
}
