package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/nodes"
)

func newNodeServer(t *testing.T) *Server {
	t.Helper()
	st, err := nodes.NewStore(filepath.Join(t.TempDir(), "nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &Server{nodes: st}
}

func addNode(t *testing.T, s *Server, body string) (*httptest.ResponseRecorder, nodes.Public) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleAddNode(rec, httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(body)))
	var out nodes.Public
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func listNodes(t *testing.T, s *Server) []nodes.Public {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleListNodes(rec, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
	var out []nodes.Public
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("list: %v (%s)", err, rec.Body)
	}
	return out
}

// Registering a gateway and marking it an exit is one request for a script. When
// create ignored the exit fields it answered 201 and produced no exit at all —
// the switch was on in the caller's request and off in the gateway.
func TestAddNodeAppliesTheExitFieldsItWasGiven(t *testing.T) {
	s := newNodeServer(t)
	rec, n := addNode(t, s, `{"name":"gw-cloud","url":"http://10.9.9.9:21585","token":"tp_secret",
		"as_exit":true,"proxy_host":"10.9.9.9","proxy_port":21584,"proxy_user":"laptop","proxy_pass":"laptop-pw"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if !n.AsExit || n.ProxyPort != 21584 || n.ProxyUser != "laptop" {
		t.Fatalf("exit fields were dropped: %+v", n)
	}
	if !n.HasProxyPass {
		t.Fatal("the proxy password was dropped")
	}
	// Secrets stay server-side even on the response to the request that set them.
	if strings.Contains(rec.Body.String(), "tp_secret") || strings.Contains(rec.Body.String(), "laptop-pw") {
		t.Fatalf("create response leaks a secret: %s", rec.Body)
	}
	// And it really is in the registry as an exit, not just in the response.
	list := listNodes(t, s)
	var found bool
	for _, g := range list {
		if g.Name == "gw-cloud" {
			found = g.AsExit
		}
	}
	if !found {
		t.Fatalf("gw-cloud is not a registered exit: %+v", list)
	}
}

// An exit with nowhere to dial is a switch that does nothing, so the store
// refuses it — and then the half-registered gateway must not survive, or the
// caller sees a 400 and a gateway appears anyway.
func TestAddNodeRollsBackWhenTheExitIsIncomplete(t *testing.T) {
	s := newNodeServer(t)
	rec, _ := addNode(t, s, `{"name":"gw-broken","url":"","as_exit":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	for _, g := range listNodes(t, s) {
		if g.Name == "gw-broken" {
			t.Fatalf("a refused registration was kept: %+v", g)
		}
	}
}

// The plain shape still works, and gets no exit by accident.
func TestAddNodeWithoutExitFields(t *testing.T) {
	s := newNodeServer(t)
	rec, n := addNode(t, s, `{"name":"gw-plain","url":"http://10.9.9.10:21585","token":"tp_x"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if n.AsExit {
		t.Fatal("a gateway must not become an exit unless asked")
	}
}
