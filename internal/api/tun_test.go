package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/tuncfg"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestTUNHandlers(t *testing.T) {
	store, err := tuncfg.NewStore(filepath.Join(t.TempDir(), "tun.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{tun: store}

	rr := httptest.NewRecorder()
	s.handleGetTUN(rr, httptest.NewRequest(http.MethodGet, "/api/tun", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status %d", rr.Code)
	}
	var got apitypes.TUNConfig
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.AutoRedirect {
		t.Fatalf("default auto_redirect should be true: %+v", got)
	}

	body, _ := json.Marshal(apitypes.TUNConfig{
		Stack: "system", StrictRoute: true, AutoRedirect: false,
		Address: []string{"198.18.0.1/30"},
	})
	rr = httptest.NewRecorder()
	s.handleSetTUN(rr, httptest.NewRequest(http.MethodPut, "/api/tun", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT status %d body %s", rr.Code, rr.Body.String())
	}
	cur := store.Get()
	if cur.AutoRedirect || cur.Stack != "system" || len(cur.Address) != 1 {
		t.Fatalf("store after PUT: %+v", cur)
	}

	bad, _ := json.Marshal(apitypes.TUNConfig{Stack: "gvisor", Address: []string{"nope"}})
	rr = httptest.NewRecorder()
	s.handleSetTUN(rr, httptest.NewRequest(http.MethodPut, "/api/tun", bytes.NewReader(bad)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad address status %d want 400", rr.Code)
	}
}
