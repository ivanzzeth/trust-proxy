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

func TestExportSubscription(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(apitypes.SubscriptionExport{
			ID: "abc", Name: "airport", URL: "https://x.example/sub?token=t", UserAgent: "clash-verge/v2.0.0",
		})
	}))
	t.Cleanup(srv.Close)

	c := New(Options{APIBaseURL: srv.URL, Token: "tp_secret"})
	out, err := c.ExportSubscription("abc")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodGet || gotPath != "/api/subscriptions/abc/export" {
		t.Fatalf("got %s %s", gotMethod, gotPath)
	}
	if gotAuth != "Bearer tp_secret" {
		t.Fatalf("token not sent: %q", gotAuth)
	}
	if out.URL != "https://x.example/sub?token=t" || out.UserAgent != "clash-verge/v2.0.0" {
		t.Fatalf("decoded %+v", out)
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
