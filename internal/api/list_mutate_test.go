package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
)

func doJSON(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestMutateWhitelistAddAndRemove(t *testing.T) {
	s := newLivePolicyServer(t)

	rec := doJSON(s.handleAddWhitelist, `{"type":"domain","value":"new.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("add: status=%d body=%s", rec.Code, rec.Body)
	}
	var got whitelist.Rules
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range got.Domains {
		if d == "new.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("added domain missing from response: %v", got.Domains)
	}

	rec = doJSON(s.handleDelWhitelist, `{"type":"domain","value":"new.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove: status=%d body=%s", rec.Code, rec.Body)
	}
	for _, d := range s.wl.Get().Domains {
		if d == "new.example" {
			t.Fatal("domain still present after remove")
		}
	}
}

func TestMutateWhitelistUnknownType(t *testing.T) {
	s := newLivePolicyServer(t)
	rec := doJSON(s.handleAddWhitelist, `{"type":"bogus","value":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown type, got %d: %s", rec.Code, rec.Body)
	}
}

func TestMutateWhitelistRollsBackOnApplyFailure(t *testing.T) {
	s := newLivePolicyServer(t)
	before := s.wl.Get()
	s.wlApplier = failingWLApplier{}

	rec := doJSON(s.handleAddWhitelist, `{"type":"domain","value":"should-not-stick.example"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on apply failure, got %d: %s", rec.Code, rec.Body)
	}
	after := s.wl.Get()
	if len(after.Domains) != len(before.Domains) {
		t.Fatalf("store must be rolled back: before=%v after=%v", before.Domains, after.Domains)
	}
	for _, d := range after.Domains {
		if d == "should-not-stick.example" {
			t.Fatal("rolled-back store still contains the rejected domain")
		}
	}
}

type failingWLApplier struct{}

func (failingWLApplier) SetWhitelist(whitelist.Rules) error { return errFake }
