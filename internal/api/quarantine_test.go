package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

type recordingQuarApplier struct {
	last quarantine.List
	err  error
}

func (r *recordingQuarApplier) ApplyQuarantine(l quarantine.List) error {
	r.last = l
	return r.err
}

type recordingWLApplier struct {
	last whitelist.Rules
	err  error
}

func (r *recordingWLApplier) SetWhitelist(rules whitelist.Rules) error {
	r.last = rules
	return r.err
}

func newQuarantineServer(t *testing.T) (*Server, *recordingQuarApplier, *recordingWLApplier) {
	t.Helper()
	dir := t.TempDir()
	quar, err := quarantine.NewStore(dir + "/quarantine.json")
	if err != nil {
		t.Fatal(err)
	}
	wl, err := whitelist.NewStore(dir + "/whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	qa := &recordingQuarApplier{}
	wa := &recordingWLApplier{}
	s := &Server{quar: quar, quarApplier: qa, wl: wl, wlApplier: wa}
	return s, qa, wa
}

// Frp-shaped false positive: auto-ban quarantined the EIP. Operator recovery
// must both lift the L1 floor AND grant Permit — release alone leaves Strict
// default-deny looking identical to "still banned".
func TestPermitQuarantine_ReleasesAndAddsPermit(t *testing.T) {
	s, qa, wa := newQuarantineServer(t)
	if _, err := s.quar.Add("", "47.108.206.242", "large upload to non-whitelist destination (process=frpc, dest=47.108.206.242:7000)"); err != nil {
		t.Fatal(err)
	}

	rec := doJSON(s.handlePermitQuarantine, `{"value":"47.108.206.242/32"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got apitypes.PermitQuarantineResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Permitted.Type != "ip" || got.Permitted.Value != "47.108.206.242/32" {
		t.Fatalf("permitted = %+v", got.Permitted)
	}
	if len(got.Quarantine) != 0 {
		t.Fatalf("quarantine still has %v", got.Quarantine)
	}
	if len(s.quar.Get().Entries) != 0 {
		t.Fatal("store still quarantined")
	}
	found := false
	for _, ip := range s.wl.Get().IPs {
		if ip == "47.108.206.242/32" {
			found = true
		}
	}
	if !found {
		t.Fatalf("permit missing from whitelist: %v", s.wl.Get().IPs)
	}
	if len(qa.last.Entries) != 0 {
		t.Fatalf("applier saw leftover quarantine: %v", qa.last.Entries)
	}
	found = false
	for _, ip := range wa.last.IPs {
		if ip == "47.108.206.242/32" {
			found = true
		}
	}
	if !found {
		t.Fatalf("whitelist applier missing IP: %v", wa.last.IPs)
	}
}

func TestPermitQuarantine_NotFound(t *testing.T) {
	s, _, _ := newQuarantineServer(t)
	rec := doJSON(s.handlePermitQuarantine, `{"value":"203.0.113.9/32"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body)
	}
}

func TestPermitQuarantine_Domain(t *testing.T) {
	s, _, _ := newQuarantineServer(t)
	if _, err := s.quar.Add("evil.example", "", "threat-intel auto-block"); err != nil {
		t.Fatal(err)
	}
	rec := doJSON(s.handlePermitQuarantine, `{"value":"evil.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got apitypes.PermitQuarantineResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Permitted.Type != "domain" || got.Permitted.Value != "evil.example" {
		t.Fatalf("permitted = %+v", got.Permitted)
	}
	found := false
	for _, d := range s.wl.Get().Domains {
		if d == "evil.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("domain not on whitelist: %v", s.wl.Get().Domains)
	}
}

func TestStatusIncludesQuarantineCount(t *testing.T) {
	s, _, _ := newQuarantineServer(t)
	if _, err := s.quar.Add("", "203.0.113.10", "exfil"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	s.handleStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var st map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	n, ok := st["quarantine"].(float64)
	if !ok || int(n) != 1 {
		t.Fatalf("quarantine count = %v (%T), want 1", st["quarantine"], st["quarantine"])
	}
}
