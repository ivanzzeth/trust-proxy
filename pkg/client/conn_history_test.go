package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// `conn ls` must go through our own API, not straight to Clash with a secret read
// off the disk.
//
// It built a raw Clash client and looked for the secret in "data/clash-secret" — a
// *relative* path, so it only ever worked from inside a checkout that happened to
// have a data directory. On any real install it read nothing, sent no secret, and
// got 401. Which is the same mistake this project already fixed once for -c, whose
// default used to be a repo-relative configs/config.json.
//
// Reading it from the right absolute path would not fix it either: the data
// directory is root-owned and 0700, so an unprivileged CLI cannot read the secret at
// all — by design, and the same reason the browser never sees it. The backend
// already proxies Clash, so the CLI uses that, authenticating the way it does
// everywhere else.
func TestConnectionsGoThroughOurAPI(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"downloadTotal": 10, "uploadTotal": 20,
			"connections": []map[string]any{{"id": "c1", "upload": 1, "download": 2}},
		})
	}))
	defer srv.Close()

	c := New(Options{APIBaseURL: srv.Listener.Addr().String(), Token: "tp_test"})
	snap, err := c.APIConnections()
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/connections" {
		t.Fatalf("hit %q, want /api/connections (not the Clash port directly)", gotPath)
	}
	if gotAuth != "Bearer tp_test" {
		t.Fatalf("no API key sent: %q", gotAuth)
	}
	if len(snap.Connections) != 1 || snap.Connections[0].ID != "c1" {
		t.Fatalf("decoded %+v", snap)
	}
}

func TestKillConnectionGoesThroughOurAPI(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(Options{APIBaseURL: srv.Listener.Addr().String(), Token: "tp_test"})
	if err := c.APIKillConnection("c1"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/api/connections/c1" {
		t.Fatalf("sent %s %s, want DELETE /api/connections/c1", gotMethod, gotPath)
	}
}

// History comes back typed, so a field name that does not exist is a compile error
// rather than an empty column.
//
// The renderer read closed_at / host / upload / download / outbound out of a
// map[string]any. The record's JSON names are t / h / u / dn / o. Every field missed,
// so `history ls` printed the right number of rows with nothing in them and `<nil>`
// where the byte counts go — while --json looked perfect, because that path never
// touches the names. Nothing could catch it: there is no type, so there is nothing
// to disagree with.
func TestHistoryDecodesIntoTypedRecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exactly what internal/history writes.
		_, _ = w.Write([]byte(`{"total":2,"items":[
			{"t":"2026-07-28T20:00:00Z","h":"example.com","o":"proxy","u":2048,"dn":10240,"ms":413},
			{"t":"2026-07-28T19:59:00Z","h":"api.ipify.org","o":"direct","u":846,"dn":3072,"x":true}
		]}`))
	}))
	defer srv.Close()

	c := New(Options{APIBaseURL: srv.Listener.Addr().String(), Token: "tp_test"})
	page, err := c.HistoryPage("", 10)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("decoded %+v", page)
	}
	first := page.Items[0]
	if first.Host != "example.com" {
		t.Fatalf("host = %q", first.Host)
	}
	if first.Up != 2048 || first.Down != 10240 {
		t.Fatalf("byte counts came through as %d/%d", first.Up, first.Down)
	}
	if first.Outbound != "proxy" || first.Time == "" {
		t.Fatalf("outbound=%q time=%q", first.Outbound, first.Time)
	}
	if !page.Items[1].Denied {
		t.Fatal("the denied flag did not decode")
	}
}
