package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// recorded is one request the fake backend saw: enough to assert the SDK hit the
// right endpoint with the right verb and body.
type recorded struct {
	method string
	path   string // decoded (what a handler sees)
	uri    string // as sent on the wire, still escaped
	query  string
	body   string
	auth   string
}

// fakeAPI answers any request with reply and records what it was asked.
func fakeAPI(t *testing.T, reply string) (*Client, *[]recorded) {
	t.Helper()
	var seen []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, recorded{
			method: r.Method, path: r.URL.Path, uri: r.RequestURI, query: r.URL.RawQuery,
			body: strings.TrimSpace(string(b)), auth: r.Header.Get("Authorization"),
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return New(Options{APIBaseURL: srv.URL, Token: "sekret"}), &seen
}

func last(t *testing.T, seen *[]recorded) recorded {
	t.Helper()
	if len(*seen) == 0 {
		t.Fatal("backend saw no request")
	}
	return (*seen)[len(*seen)-1]
}

// Every call must carry the bearer token, or a probe with --api-token rejects the
// CLI with a 401 that looks like a connectivity problem.
func TestTokenIsSent(t *testing.T) {
	c, seen := fakeAPI(t, `{}`)
	if _, err := c.Status(); err != nil {
		t.Fatal(err)
	}
	if got := last(t, seen).auth; got != "Bearer sekret" {
		t.Fatalf("Authorization = %q, want Bearer sekret", got)
	}
}

// The three ACL stores are distinct endpoints; mapping the CLI's friendly name to
// the wrong one would silently write to the wrong axis (e.g. granting egress when
// the user asked for no-proxy).
func TestListKindMapsToItsOwnEndpoint(t *testing.T) {
	cases := map[string]string{
		"permit":   "/api/whitelist",
		"deny":     "/api/blacklist",
		"no-proxy": "/api/directlist",
	}
	for name, wantPath := range cases {
		kind, err := ValidListKind(name)
		if err != nil {
			t.Fatalf("ValidListKind(%q): %v", name, err)
		}
		c, seen := fakeAPI(t, `{"domains":["x.tp"]}`)
		if _, err := c.AddListEntry(kind, "domain", "x.tp"); err != nil {
			t.Fatal(err)
		}
		r := last(t, seen)
		if r.path != wantPath || r.method != http.MethodPost {
			t.Fatalf("%s add -> %s %s, want POST %s", name, r.method, r.path, wantPath)
		}
		if !strings.Contains(r.body, `"type":"domain"`) || !strings.Contains(r.body, `"value":"x.tp"`) {
			t.Fatalf("%s add body = %s", name, r.body)
		}
	}
	if _, err := ValidListKind("whatever"); err == nil {
		t.Fatal("an unknown list name must be rejected, not silently mapped")
	}
}

func TestListDeleteUsesDelete(t *testing.T) {
	c, seen := fakeAPI(t, `{}`)
	if _, err := c.DeleteListEntry(ListPermit, "ip", "1.2.3.4/32"); err != nil {
		t.Fatal(err)
	}
	r := last(t, seen)
	if r.method != http.MethodDelete || r.path != "/api/whitelist" {
		t.Fatalf("got %s %s", r.method, r.path)
	}
}

// A guarded mode switch is the remote-safety feature; the guard must reach the
// backend, and must be omitted (not sent as 0) when disabled.
func TestSetModeGuard(t *testing.T) {
	c, seen := fakeAPI(t, `{"mode":"tun"}`)
	if _, err := c.SetMode("tun", 60); err != nil {
		t.Fatal(err)
	}
	if body := last(t, seen).body; !strings.Contains(body, `"guard_seconds":60`) {
		t.Fatalf("body = %s, want guard_seconds", body)
	}
	if _, err := c.SetMode("manual", 0); err != nil {
		t.Fatal(err)
	}
	if body := last(t, seen).body; strings.Contains(body, "guard_seconds") {
		t.Fatalf("body = %s, want no guard_seconds when disabled", body)
	}
}

// Ids/tags go into the path, so they must be escaped — a pack named "AI (other)"
// or a tag with a slash would otherwise hit a different route.
func TestPathParamsAreEscaped(t *testing.T) {
	c, seen := fakeAPI(t, `{"rules":[]}`) // these endpoints return the store doc
	if _, err := c.PatchPack("AI (other)", false); err != nil {
		t.Fatal(err)
	}
	// On the wire the space stays escaped; a handler sees it decoded.
	if u := last(t, seen).uri; u != "/api/customrules/packs/AI%20%28other%29" {
		t.Fatalf("uri = %q", u)
	}
	if err := c.DeleteRuleSet("geosite/cn"); err != nil {
		t.Fatal(err)
	}
	// The slash must stay escaped, or the tag would split into two path segments
	// and hit a different route entirely.
	if u := last(t, seen).uri; u != "/api/rulesets/geosite%2Fcn" {
		t.Fatalf("uri = %q, want the slash escaped", u)
	}
}

func TestQueryFilters(t *testing.T) {
	c, seen := fakeAPI(t, `{"items":[]}`)
	if _, err := c.Detections("threat", "evil.tp", 10); err != nil {
		t.Fatal(err)
	}
	q := last(t, seen).query
	for _, want := range []string{"kind=threat", "q=evil.tp", "limit=10"} {
		if !strings.Contains(q, want) {
			t.Fatalf("query = %q, want %q", q, want)
		}
	}
	// Zero/empty filters must not be sent at all (limit=0 would mean "none").
	if _, err := c.History("", 0); err != nil {
		t.Fatal(err)
	}
	if q := last(t, seen).query; q != "" {
		t.Fatalf("query = %q, want empty", q)
	}
}

// The DNS round-trip carries the direct-resolver knobs; dropping them on the way
// out would silently re-break domestic routing.
func TestDNSRoundTrip(t *testing.T) {
	c, seen := fakeAPI(t, `{"servers":[],"rules":[],"direct_server":"119.29.29.29"}`)
	in := apitypes.DNSConfig{
		Servers:      []apitypes.DNSServer{{Tag: "doh", Type: "https", Server: "8.8.8.8", Detour: "proxy"}},
		Final:        "doh",
		DirectServer: "119.29.29.29",
	}
	got, err := c.SetDNS(in)
	if err != nil {
		t.Fatal(err)
	}
	r := last(t, seen)
	if r.method != http.MethodPut || r.path != "/api/dns" {
		t.Fatalf("got %s %s", r.method, r.path)
	}
	var sent apitypes.DNSConfig
	if err := json.Unmarshal([]byte(r.body), &sent); err != nil {
		t.Fatal(err)
	}
	if sent.DirectServer != "119.29.29.29" || sent.Final != "doh" {
		t.Fatalf("sent = %+v", sent)
	}
	if got.DirectServer != "119.29.29.29" {
		t.Fatalf("decoded = %+v", got)
	}
}

// The custom-rule / rule-set endpoints return their whole store document. The
// SDK must unwrap it — decoding it as a bare array is what broke every one of
// those commands the first time they hit a real backend.
func TestStoreDocumentsAreUnwrapped(t *testing.T) {
	c, _ := fakeAPI(t, `{"rules":[{"id":"abc123","match":"domain_suffix","value":"intranet.tp","egress":"direct","enabled":true}]}`)
	rules, err := c.CustomRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Value != "intranet.tp" {
		t.Fatalf("custom rules = %+v", rules)
	}
	added, err := c.AddCustomRule(apitypes.CustomRule{Match: "domain", Value: "x.tp"})
	if err != nil || len(added) != 1 {
		t.Fatalf("add returned %+v (%v)", added, err)
	}

	c2, _ := fakeAPI(t, `{"sets":[{"tag":"geosite-cn","role":"route-direct","type":"remote","enabled":true}]}`)
	sets, err := c2.RuleSets()
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 1 || sets[0].Role != "route-direct" {
		t.Fatalf("rule sets = %+v", sets)
	}

	c3, _ := fakeAPI(t, `{"rules":[{"id":"r1"}],"rule_sets":[{"tag":"geosite-claude"}]}`)
	res, err := c3.ApplyPack("Claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 1 || len(res.RuleSets) != 1 {
		t.Fatalf("pack result = %+v", res)
	}
}

// A backend error must surface as an error with the server's message, not as an
// empty success (which a script would read as "it worked").
func TestErrorSurfacing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":"apply whitelist failed (reverted): bad ip_cidr"}`)
	}))
	defer srv.Close()
	c := New(Options{APIBaseURL: srv.URL})
	_, err := c.AddListEntry(ListPermit, "ip", "not-an-ip")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "bad ip_cidr") {
		t.Fatalf("error = %v, want the backend message", err)
	}
}
