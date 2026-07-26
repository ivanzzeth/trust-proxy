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

// No-Proxy carries always-on built-in ranges the gateway owns; a client that
// drops them shows a list the user cannot act on and hides why LAN traffic is
// direct.
func TestListBuiltinsAreDecoded(t *testing.T) {
	c, _ := fakeAPI(t, `{"builtin":["10.0.0.0/8","fc00::/7"],"domains":["nas.tp"],"ips":null}`)
	list, err := c.List(ListNoProxy)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Builtin) != 2 || list.Builtin[0] != "10.0.0.0/8" {
		t.Fatalf("builtin = %v", list.Builtin)
	}
	if len(list.Domains) != 1 {
		t.Fatalf("domains = %v", list.Domains)
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
	c, seen := fakeAPI(t, `[]`)
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

// List endpoints are bare arrays, like every other list endpoint. They used to
// hand out the internal store struct ({"rules":[…]} / {"sets":[…]}), which broke
// six CLI commands and forced every client to special-case two paths; the
// inconsistency was fixed in the API rather than papered over here.
func TestListEndpointsAreBareArrays(t *testing.T) {
	c, _ := fakeAPI(t, `[{"id":"abc123","match":"domain_suffix","value":"intranet.tp","egress":"direct","enabled":true}]`)
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

	c2, _ := fakeAPI(t, `[{"tag":"geosite-cn","role":"route-direct","type":"remote","enabled":true}]`)
	sets, err := c2.RuleSets()
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 1 || sets[0].Role != "route-direct" {
		t.Fatalf("rule sets = %+v", sets)
	}

	// Applying a pack is the one non-list case: a result object carrying both
	// halves of what changed. Its rule_sets are catalog bindings (catalog_tag +
	// role), not full descriptors.
	c3, _ := fakeAPI(t, `{"rules":[{"id":"r1"}],"rule_sets":[{"catalog_tag":"geosite-claude","role":"permit+route-proxy"}]}`)
	res, err := c3.ApplyPack("Claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 1 || len(res.RuleSets) != 1 {
		t.Fatalf("pack result = %+v", res)
	}
	if res.RuleSets[0].CatalogTag != "geosite-claude" || res.RuleSets[0].Role != "permit+route-proxy" {
		t.Fatalf("pack rule set = %+v (decoded into the wrong type?)", res.RuleSets[0])
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

// Self-hosted exit generation: the CLI and the console must both reach the same
// endpoint, and the request has to carry every field or the server silently
// generates something else (e.g. port 443 when 8443 was asked for).
func TestGenerateProxy(t *testing.T) {
	c, seen := fakeAPI(t, `{"server":{"inbounds":[]},"client":{"name":"tokyo"},"share":"ss://x","gen_command":"trust-proxy proxy gen","install_script":"cat > server.json"}`)
	res, err := c.GenerateProxy(apitypes.ProxyGenRequest{Type: "vless-reality", Server: "203.0.113.9", Port: 8443, SNI: "www.microsoft.com", Name: "tokyo"})
	if err != nil {
		t.Fatal(err)
	}
	got := last(t, seen)
	if got.method != http.MethodPost || got.path != "/api/proxy-gen" {
		t.Fatalf("%s %s, want POST /api/proxy-gen", got.method, got.path)
	}
	var sent apitypes.ProxyGenRequest
	if err := json.Unmarshal([]byte(got.body), &sent); err != nil {
		t.Fatalf("body is not a ProxyGenRequest: %s", got.body)
	}
	if sent.Type != "vless-reality" || sent.Server != "203.0.113.9" || sent.Port != 8443 || sent.SNI != "www.microsoft.com" || sent.Name != "tokyo" {
		t.Fatalf("request lost fields: %+v", sent)
	}
	if res.Client["name"] != "tokyo" || res.InstallScript == "" || res.GenCommand == "" {
		t.Fatalf("result not decoded: %+v", res)
	}
}

func TestProxyProtocolsUnwrapsABareArray(t *testing.T) {
	c, seen := fakeAPI(t, `["shadowsocks","trojan"]`)
	got, err := c.ProxyProtocols()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "shadowsocks" {
		t.Fatalf("protocols = %v", got)
	}
	if p := last(t, seen).path; p != "/api/proxy-gen/protocols" {
		t.Fatalf("path %s", p)
	}
}

// Auth: the CLI and the console both go through these, so the wire shapes are
// worth pinning — a login that posts the wrong field name fails at runtime only.
func TestAuthSDK(t *testing.T) {
	c, seen := fakeAPI(t, `{"user":{"id":"u1","username":"alice","role":"admin","created_at":"now"},"expires_at":"later"}`)
	sess, err := c.Login("alice", "secret-password")
	if err != nil {
		t.Fatal(err)
	}
	got := last(t, seen)
	if got.method != http.MethodPost || got.path != "/api/auth/login" {
		t.Fatalf("%s %s", got.method, got.path)
	}
	var lr apitypes.LoginRequest
	if err := json.Unmarshal([]byte(got.body), &lr); err != nil {
		t.Fatal(err)
	}
	if lr.Username != "alice" || lr.Password != "secret-password" {
		t.Fatalf("login body = %+v", lr)
	}
	if sess.User.Role != "admin" {
		t.Fatalf("session = %+v", sess)
	}

	// Bootstrap carries the one-time code only when there is one.
	if _, err := c.Bootstrap("alice", "secret-password", "the-code"); err != nil {
		t.Fatal(err)
	}
	if b := last(t, seen).body; !strings.Contains(b, `"code":"the-code"`) {
		t.Fatalf("bootstrap body = %s", b)
	}
	if _, err := c.Bootstrap("alice", "secret-password", ""); err != nil {
		t.Fatal(err)
	}
	if b := last(t, seen).body; strings.Contains(b, "code") {
		t.Fatalf("empty code must be omitted: %s", b)
	}
}

func TestUserAdminSDK(t *testing.T) {
	c, seen := fakeAPI(t, `{"id":"u2","username":"bob","role":"user","created_at":"now"}`)
	if _, err := c.CreateUser("bob", "bob-password-long", "user"); err != nil {
		t.Fatal(err)
	}
	if p := last(t, seen).path; p != "/api/users" {
		t.Fatalf("path %s", p)
	}

	// A PATCH must send only what was asked for: an absent proxy password means
	// "leave it", an empty one means "revoke proxy access". Merging those would
	// silently take away someone's access.
	empty := ""
	if _, err := c.PatchUser("u2", apitypes.PatchUserRequest{ProxyPassword: &empty}); err != nil {
		t.Fatal(err)
	}
	got := last(t, seen)
	if got.method != http.MethodPatch || got.path != "/api/users/u2" {
		t.Fatalf("%s %s", got.method, got.path)
	}
	if got.body != `{"proxy_password":""}` {
		t.Fatalf("patch body = %s (only the set field may be sent)", got.body)
	}
	role := "admin"
	if _, err := c.PatchUser("u2", apitypes.PatchUserRequest{Role: &role}); err != nil {
		t.Fatal(err)
	}
	if b := last(t, seen).body; b != `{"role":"admin"}` {
		t.Fatalf("patch body = %s", b)
	}
}

func TestAPIKeySDK(t *testing.T) {
	c, seen := fakeAPI(t, `{"id":"k1","label":"cli","prefix":"tp_abc","created_at":"now","key":"tp_theactualkey"}`)
	created, err := c.CreateAPIKey("u1", "cli", 30)
	if err != nil {
		t.Fatal(err)
	}
	if created.Key != "tp_theactualkey" {
		t.Fatalf("the raw key must come through once: %+v", created)
	}
	got := last(t, seen)
	if got.path != "/api/users/u1/apikeys" || !strings.Contains(got.body, `"expires_in_days":30`) {
		t.Fatalf("%s %s", got.path, got.body)
	}
	if err := c.DeleteAPIKey("u1", "k1"); err != nil {
		t.Fatal(err)
	}
	if p := last(t, seen).path; p != "/api/users/u1/apikeys/k1" {
		t.Fatalf("path %s", p)
	}
}
