package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestUnapplySubscription(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewEncoder(w).Encode(apitypes.SubscriptionPublic{ID: "abc", Name: "x", Applied: false})
	}))
	t.Cleanup(srv.Close)

	c := New(Options{APIBaseURL: srv.URL})
	out, err := c.UnapplySubscription("abc")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/subscriptions/abc/unapply" {
		t.Fatalf("got %s %s", gotMethod, gotPath)
	}
	if out.Applied {
		t.Fatal("expected applied=false")
	}
}

func TestApplySubscriptionPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(apitypes.SubscriptionPublic{ID: "abc", Applied: true})
	}))
	t.Cleanup(srv.Close)

	c := New(Options{APIBaseURL: srv.URL})
	if _, err := c.ApplySubscription("abc"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/subscriptions/abc/apply" {
		t.Fatalf("path=%s", gotPath)
	}
}
