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

type fakeApplier struct{ calls int }

func (f *fakeApplier) Apply([]apitypes.Node) error { f.calls++; return nil }

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
