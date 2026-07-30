package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/detectcfg"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

type recordingDetApplier struct {
	last apitypes.DetectionConfig
	n    int
}

func (r *recordingDetApplier) ApplyDetectionConfig(c apitypes.DetectionConfig) {
	r.last = c
	r.n++
}

// The top-bar switch and the Detection page write the same setting through two
// different endpoints. The shortcut one used to poke only the live engine, so
// disposal came back on by itself at the next restart: the switch looked like
// it worked, the file said otherwise, and ApplyConfig(store) at boot won.
//
// Teeth: revert handleAutoBlock to `s.detect.SetAutoBlock(req.Enabled)` and the
// store assertion below fails.
func TestAutoBlockEndpointPersists(t *testing.T) {
	dir := t.TempDir()
	store, err := detectcfg.NewStore(filepath.Join(dir, "detection.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !store.Get().AutoBlock {
		t.Fatalf("precondition: default AutoBlock should be true, got %+v", store.Get())
	}
	applier := &recordingDetApplier{}
	s := &Server{detect: detect.New(16), detcfg: store, detApplier: applier}

	rr := httptest.NewRecorder()
	s.handleAutoBlock(rr, httptest.NewRequest(http.MethodPost, "/api/autoblock", strings.NewReader(`{"enabled":false}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST status %d body %s", rr.Code, rr.Body.String())
	}

	if store.Get().AutoBlock {
		t.Fatalf("switch did not reach the store; it will come back on at the next restart")
	}
	if applier.n != 1 || applier.last.AutoBlock {
		t.Fatalf("applier not driven from the saved config: n=%d last=%+v", applier.n, applier.last)
	}

	// It must survive a reopen of the same file — that is the restart the bug
	// was invisible across.
	reopened, err := detectcfg.NewStore(filepath.Join(dir, "detection.json"))
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Get().AutoBlock {
		t.Fatalf("AutoBlock is back on after reopening the store")
	}

	// And back on again, so the endpoint is not merely write-once.
	rr = httptest.NewRecorder()
	s.handleAutoBlock(rr, httptest.NewRequest(http.MethodPost, "/api/autoblock", strings.NewReader(`{"enabled":true}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("re-enable status %d body %s", rr.Code, rr.Body.String())
	}
	if !store.Get().AutoBlock {
		t.Fatalf("re-enable did not reach the store: %+v", store.Get())
	}
	var resp struct {
		AutoBlock bool `json:"autoBlock"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.AutoBlock {
		t.Fatalf("response should echo the saved value: %s", rr.Body.String())
	}
}

// No store wired (probe / test server): the switch still has to do something
// this run rather than 503 or silently no-op.
func TestAutoBlockWithoutStoreFallsBackToEngine(t *testing.T) {
	eng := detect.New(16)
	eng.SetAutoBlock(true)
	s := &Server{detect: eng}

	rr := httptest.NewRecorder()
	s.handleAutoBlock(rr, httptest.NewRequest(http.MethodPost, "/api/autoblock", strings.NewReader(`{"enabled":false}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if eng.AutoBlock() {
		t.Fatalf("engine still has disposal on")
	}
}
