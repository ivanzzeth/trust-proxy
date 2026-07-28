package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/subscription"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

type fakeApplier struct {
	calls int
	last  []apitypes.Node
}

func (f *fakeApplier) Apply(nodes []apitypes.Node) error {
	f.calls++
	f.last = append([]apitypes.Node(nil), nodes...)
	return nil
}

// TestHandleApplySubRefusesZeroNodes locks in the fix for a real-world bug: a
// subscription with 0 nodes (a dead link, or a refresh that returned nothing
// parseable) must never be applied — doing so collapses the gateway's proxy
// group to direct-only, silently breaking every route that depended on a
// real node.
func TestHandleApplySubRefusesZeroNodes(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badPath, []byte("not a subscription"), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := subscription.NewStore(filepath.Join(dir, "subscriptions.json"))
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := store.Add("bad", "file://"+badPath, "", "", "")
	if sub.NodeCount != 0 {
		t.Fatalf("test setup: expected 0 nodes, got %d", sub.NodeCount)
	}

	fa := &fakeApplier{}
	s := &Server{store: store, applier: fa}

	req := httptest.NewRequest(http.MethodPost, "/api/subscriptions/"+sub.ID+"/apply", nil)
	req.SetPathValue("id", sub.ID)
	rec := httptest.NewRecorder()
	s.handleApplySub(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body)
	}
	if fa.calls != 0 {
		t.Fatalf("Apply must never be called for a 0-node subscription, got %d call(s)", fa.calls)
	}
}

func TestHandleApplySubAppliesNonEmptyNodes(t *testing.T) {
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(goodPath, []byte(oneNodeYAMLForAPITest), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := subscription.NewStore(filepath.Join(dir, "subscriptions.json"))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := store.Add("good", "file://"+goodPath, "", "", "")
	if err != nil || sub.NodeCount != 1 {
		t.Fatalf("test setup: expected 1 node, got count=%d err=%v", sub.NodeCount, err)
	}

	fa := &fakeApplier{}
	s := &Server{store: store, applier: fa}

	req := httptest.NewRequest(http.MethodPost, "/api/subscriptions/"+sub.ID+"/apply", nil)
	req.SetPathValue("id", sub.ID)
	rec := httptest.NewRecorder()
	s.handleApplySub(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body)
	}
	if fa.calls != 1 {
		t.Fatalf("expected Apply to be called once, got %d", fa.calls)
	}
}

const oneNodeYAMLForAPITest = `proxies:
  - { name: "node1", type: "ss", server: "1.2.3.4", port: 8388, cipher: "aes-256-gcm", password: "pw" }
`

func TestHandleApplySubMergesMultiple(t *testing.T) {
	dir := t.TempDir()
	aPath := filepath.Join(dir, "a.yaml")
	bPath := filepath.Join(dir, "b.yaml")
	if err := os.WriteFile(aPath, []byte(oneNodeYAMLForAPITest), 0o644); err != nil {
		t.Fatal(err)
	}
	bYAML := `proxies:
  - { name: "node2", type: "ss", server: "5.6.7.8", port: 8388, cipher: "aes-256-gcm", password: "pw" }
`
	if err := os.WriteFile(bPath, []byte(bYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := subscription.NewStore(filepath.Join(dir, "subscriptions.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.Add("a", "file://"+aPath, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.Add("b", "file://"+bPath, "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	fa := &fakeApplier{}
	s := &Server{store: store, applier: fa}

	req := httptest.NewRequest(http.MethodPost, "/api/subscriptions/"+a.ID+"/apply", nil)
	req.SetPathValue("id", a.ID)
	rec := httptest.NewRecorder()
	s.handleApplySub(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply a: %d %s", rec.Code, rec.Body)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/subscriptions/"+b.ID+"/apply", nil)
	req.SetPathValue("id", b.ID)
	rec = httptest.NewRecorder()
	s.handleApplySub(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply b: %d %s", rec.Code, rec.Body)
	}
	if fa.calls != 2 {
		t.Fatalf("calls=%d want 2", fa.calls)
	}
	if len(fa.last) != 2 {
		t.Fatalf("merged nodes=%d want 2", len(fa.last))
	}
	a2, _ := store.Get(a.ID)
	b2, _ := store.Get(b.ID)
	if !a2.Applied || !b2.Applied {
		t.Fatalf("both must stay applied")
	}
}

func TestHandleUnapplySub(t *testing.T) {
	dir := t.TempDir()
	aPath := filepath.Join(dir, "a.yaml")
	bPath := filepath.Join(dir, "b.yaml")
	_ = os.WriteFile(aPath, []byte(oneNodeYAMLForAPITest), 0o644)
	_ = os.WriteFile(bPath, []byte(`proxies:
  - { name: "node2", type: "ss", server: "5.6.7.8", port: 8388, cipher: "aes-256-gcm", password: "pw" }
`), 0o644)
	store, _ := subscription.NewStore(filepath.Join(dir, "subscriptions.json"))
	a, _ := store.Add("a", "file://"+aPath, "", "", "")
	b, _ := store.Add("b", "file://"+bPath, "", "", "")
	fa := &fakeApplier{}
	s := &Server{store: store, applier: fa}

	for _, id := range []string{a.ID, b.ID} {
		req := httptest.NewRequest(http.MethodPost, "/api/subscriptions/"+id+"/apply", nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.handleApplySub(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("apply %s: %d", id, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/subscriptions/"+a.ID+"/unapply", nil)
	req.SetPathValue("id", a.ID)
	rec := httptest.NewRecorder()
	s.handleUnapplySub(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unapply: %d %s", rec.Code, rec.Body)
	}
	a2, _ := store.Get(a.ID)
	if a2.Applied {
		t.Fatal("a still applied")
	}
	if len(fa.last) != 1 {
		t.Fatalf("after unapply nodes=%d want 1", len(fa.last))
	}
}

func TestHandleDeleteSubReappliesRemaining(t *testing.T) {
	dir := t.TempDir()
	aPath := filepath.Join(dir, "a.yaml")
	bPath := filepath.Join(dir, "b.yaml")
	_ = os.WriteFile(aPath, []byte(oneNodeYAMLForAPITest), 0o644)
	_ = os.WriteFile(bPath, []byte(`proxies:
  - { name: "node2", type: "ss", server: "5.6.7.8", port: 8388, cipher: "aes-256-gcm", password: "pw" }
`), 0o644)
	store, _ := subscription.NewStore(filepath.Join(dir, "subscriptions.json"))
	a, _ := store.Add("a", "file://"+aPath, "", "", "")
	b, _ := store.Add("b", "file://"+bPath, "", "", "")
	fa := &fakeApplier{}
	s := &Server{store: store, applier: fa}
	for _, id := range []string{a.ID, b.ID} {
		req := httptest.NewRequest(http.MethodPost, "/api/subscriptions/"+id+"/apply", nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.handleApplySub(rec, req)
	}
	callsBefore := fa.calls
	req := httptest.NewRequest(http.MethodDelete, "/api/subscriptions/"+a.ID, nil)
	req.SetPathValue("id", a.ID)
	rec := httptest.NewRecorder()
	s.handleDeleteSub(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if fa.calls != callsBefore+1 {
		t.Fatalf("expected re-apply after delete, calls=%d", fa.calls)
	}
	if len(fa.last) != 1 {
		t.Fatalf("remaining nodes=%d want 1", len(fa.last))
	}
	if _, ok := store.Get(b.ID); !ok {
		t.Fatal("b should remain")
	}
}
