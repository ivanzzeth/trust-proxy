package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Wire-shape contract for the list endpoints. These two used to hand out the
// internal store struct ({"rules":[…]} / {"sets":[…]}) while every other list
// endpoint returned a bare array, which forced each client to special-case them
// — and silently broke six CLI commands the first time they met a real backend.
// Empty must be [] and never null, or a client that maps over the result blows up.
func TestListEndpointsReturnBareArrays(t *testing.T) {
	dir := t.TempDir()
	crStore, err := customrules.NewStore(dir + "/customrules.json")
	if err != nil {
		t.Fatal(err)
	}
	rsStore, err := ruleset.NewStore(dir + "/rulesets.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crStore.Add(apitypes.CustomRule{Match: "domain_suffix", Value: "intranet.tp", Action: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := rsStore.Add(apitypes.RuleSet{Tag: "geosite-cn", Name: "cn", Type: "remote", Format: "binary", URL: "https://example.invalid/cn.srs", Role: apitypes.RuleRoleRouteDirect, UpdateInterval: "1d", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	s := &Server{cr: crStore, rs: rsStore}
	handlers := map[string]http.HandlerFunc{
		"/api/customrules": s.handleListCustomRules,
		"/api/rulesets":    s.handleListRuleSets,
	}

	for path, h := range handlers {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d: %s", path, rec.Code, rec.Body.String())
		}
		body := strings.TrimSpace(rec.Body.String())
		if !strings.HasPrefix(body, "[") {
			t.Fatalf("%s returned %s, want a bare JSON array", path, body)
		}
		var items []map[string]any
		if err := json.Unmarshal([]byte(body), &items); err != nil {
			t.Fatalf("%s: %v (body %s)", path, err, body)
		}
		if len(items) != 1 {
			t.Fatalf("%s returned %d items, want 1", path, len(items))
		}
	}
}

// An empty store must still serialize as [] (null crashes clients that map over
// the result — it already did once, on the Proxies page).
func TestEmptyListEndpointsAreEmptyArrays(t *testing.T) {
	dir := t.TempDir()
	crStore, err := customrules.NewStore(dir + "/customrules.json")
	if err != nil {
		t.Fatal(err)
	}
	rsStore, err := ruleset.NewStore(dir + "/rulesets.json")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cr: crStore, rs: rsStore}
	handlers := map[string]http.HandlerFunc{
		"/api/customrules": s.handleListCustomRules,
		"/api/rulesets":    s.handleListRuleSets,
	}

	for path, h := range handlers {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
			t.Fatalf("%s on an empty store returned %q, want []", path, got)
		}
	}
}
