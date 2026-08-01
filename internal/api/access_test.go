package api

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/authn"
	"github.com/ivanzzeth/trust-proxy/internal/users"
)

// Four separate holes, one mechanism: the access level was computed by matching
// the request path against string prefixes, so every new route and every new
// prefix silently re-decided who could reach what. These tests pin the four
// outcomes; access.go replaces the guessing with a declared table.

// The reverse proxy must never be reachable without a credential.
//
// path0 strips the /api/nodes/{id} prefix so a forwarded request is judged by what
// it asks for, which is right for granularity and was wrong for anonymity: the
// stripped path could land in publicPaths, withAuth returned before authenticating,
// and handleNodeProxy forwarded anyway — injecting the stored probe token. Any
// unauthenticated caller who could reach the brain got a credential-carrying relay
// onto every registered gateway: password guessing against a remote /auth/login,
// remote claim attempts against /auth/bootstrap, /auth/register wherever a probe
// had signup open.
//
// Judged by the forwarded path, floored at "logged in". Nothing that injects
// somebody else's credential can be public.
func TestNodeProxyIsNeverAnonymous(t *testing.T) {
	s, us, _, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/nodes/n1/health"},
		{"GET", "/api/nodes/n1/auth/state"},
		{"POST", "/api/nodes/n1/auth/login"},
		{"POST", "/api/nodes/n1/auth/bootstrap"},
		{"POST", "/api/nodes/n1/auth/register"},
		{"POST", "/api/nodes/n1/auth/logout"},
		{"GET", "/api/nodes/n1/auth/ticket"},
	} {
		r := req(tc.method, tc.path)
		r.Host = "127.0.0.1:21585"
		if got := serve(s, r).Code; got != 401 {
			t.Errorf("anonymous %s %s: got %d, want 401 — this is a credential-injecting "+
				"relay onto a remote gateway", tc.method, tc.path, got)
		}
	}
}

// The same paths unproxied stay public: that is how a fresh gateway gets claimed
// and how the console shows a login form. The floor applies to the relay, not to
// the endpoints.
func TestLocalAuthEndpointsStayPublic(t *testing.T) {
	s, _, _, _ := newAuthServer(t)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/health"},
		{"GET", "/api/auth/state"},
	} {
		if got := serve(s, req(tc.method, tc.path)).Code; got != 200 {
			t.Errorf("%s %s: got %d, want 200", tc.method, tc.path, got)
		}
	}
}

// Public mutations need the Origin check too.
//
// The condition was `need != accessPublic && isMutation(...) && !originOK(...)`,
// so POST /api/auth/{bootstrap,register,login,logout} had no CSRF defence at all.
// Any page the operator visits could POST to the loopback API with credentials the
// attacker chose and become the first admin of a root-privileged gateway — no
// response read required, and loopback is a secure context so mixed-content
// blocking does not apply. Even as a pure land-grab it is a permanent denial of
// ownership.
func TestPublicMutationsAreOriginChecked(t *testing.T) {
	s, _, _, _ := newAuthServer(t)
	for _, path := range []string{
		"/api/auth/bootstrap", "/api/auth/register", "/api/auth/login", "/api/auth/logout",
	} {
		r := req("POST", path)
		r.Host = "127.0.0.1:21585"
		r.Header.Set("Origin", "http://evil.example")
		if got := serve(s, r).Code; got != 403 {
			t.Errorf("cross-origin POST %s: got %d, want 403 — a web page can claim this gateway", path, got)
		}
	}
	// Same origin still works, and so does a request with no Origin at all (the
	// CLI, curl, the desktop shell).
	r := req("POST", "/api/auth/login")
	r.Host = "127.0.0.1:21585"
	r.Header.Set("Origin", "http://127.0.0.1:21585")
	if got := serve(s, r).Code; got != 200 {
		t.Errorf("same-origin login: got %d, want 200", got)
	}
	if got := serve(s, req("POST", "/api/auth/login")).Code; got != 200 {
		t.Errorf("login with no Origin: got %d, want 200", got)
	}
}

// The latency probe dials wherever the caller points it, outside all policy.
//
// /api/proxies was in the read-only-for-users list and the check was a prefix
// match, so a client role got GET /api/proxies/{name}/delay. The handler passed the
// caller's `url` straight through, and urltest calls detour.DialContext directly —
// no route.rules, so no deny floor, no Permit gate, no quarantine, and no tracker,
// meaning not even a detection event. `name` may be `direct`. That is an
// arbitrary-destination request with an attacker-chosen path, plus a port-scanning
// oracle in the timing, handed to exactly the caller the gate exists to contain.
// Proxy names from airport subscriptions almost always contain spaces
// ("香港 12", "35.77 GB | 300 GB"). The access probe used to feed the decoded
// path into httptest.NewRequest, which panics on a literal space — so every
// latency test for a real node closed the TCP socket with no HTTP response,
// and the UI reported "timeout".
func TestLevelOfSurvivesSpacesInProxyNames(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("levelOf panicked on a spaced proxy name: %v", rec)
		}
	}()
	for _, path := range []string{
		"/api/proxies/香港 12/delay",
		"/api/proxies/35.77 GB | 300 GB/delay",
		"/api/proxies/foo%20bar/delay",
	} {
		if got := levelOf(http.MethodGet, path); got != accessAdmin {
			t.Fatalf("levelOf(%q) = %v, want accessAdmin (delay is admin-only)", path, got)
		}
	}
}

// End-to-end: withAuth must answer a spaced delay URL with an HTTP status, not
// an empty TCP close. Clash itself may be nil — 503 is fine; panic is not.
func TestProxyDelayWithSpaceInNameDoesNotDropTheConnection(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	admin, _ := us.Create("admin", "admin-password-long", users.RoleAdmin)
	tok, _, _ := a.Issue(admin)

	r := req("GET", "/api/proxies/"+url.PathEscape("香港 12")+"/delay?timeout=1000&url=https://www.gstatic.com/generate_204")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	rec := serve(s, r)
	if rec.Code == 0 {
		t.Fatal("handler produced no HTTP status — the old panic path closed the socket raw")
	}
	// No clash client wired in this harness → 503; what matters is we got a response.
	if rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusOK {
		t.Fatalf("status = %d body %q, want 503 (no clash) or 200", rec.Code, rec.Body.String())
	}
}

func TestProxyDelayIsNotReachableByAClient(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	tok, _, _ := a.Issue(bob)

	r := req("GET", "/api/proxies/direct/delay?url=http://169.254.169.254/latest/meta-data/")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 403 {
		t.Fatalf("a client reached the latency probe: got %d, want 403", got)
	}
	// Listing proxies is still an ordinary read.
	r = req("GET", "/api/proxies")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 200 {
		t.Fatalf("a client cannot list proxies: got %d, want 200", got)
	}
}

// Observability that is not scoped to the caller is not observability for a
// client. /api/logs is the whole gateway log stream — every other account's
// destinations — and it was readable by any logged-in user, which defeats the
// per-caller filtering in scope.go entirely. The same applies to the aggregate
// */stats endpoints, whose sibling list endpoints *are* scoped.
func TestUnscopedObservabilityIsAdminOnly(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	tok, _, _ := a.Issue(bob)

	for _, path := range []string{
		"/api/logs",
		"/api/history/stats",
		"/api/detections/stats",
		"/api/dns-queries/stats",
		"/api/fingerprints",
		"/api/netcheck",
	} {
		r := req("GET", path)
		r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
		if got := serve(s, r).Code; got != 403 {
			t.Errorf("a client read %s: got %d, want 403 — it is gateway-wide and unscoped", path, got)
		}
	}
	// The scoped siblings stay readable.
	for _, path := range []string{"/api/history", "/api/detections", "/api/connections"} {
		r := req("GET", path)
		r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
		if got := serve(s, r).Code; got != 200 {
			t.Errorf("a client cannot read its own %s: got %d, want 200", path, got)
		}
	}
}

// Reading the policy is reading the policy. internal/users promises a client
// "cannot read the policy" and the matrix test proves GET /api/whitelist is 403 —
// but /api/effective-rules renders the whole layered policy including permitted
// domains, device CIDRs and process names, and it was on the read-only list.
func TestEffectiveRulesIsAdminOnly(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	tok, _, _ := a.Issue(bob)

	for _, path := range []string{"/api/effective-rules", "/api/rules"} {
		r := req("GET", path)
		r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
		if got := serve(s, r).Code; got != 403 {
			t.Errorf("a client read %s: got %d, want 403", path, got)
		}
	}
}

// The export endpoint is the only one that hands a subscription URL back out in
// the clear, and a subscription URL is an airport account. Every other
// /api/subscriptions* route is admin-only; this one especially has to be, because
// its whole job is to defeat the redaction the rest of them rely on.
func TestSubscriptionExportIsAdminOnly(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	tok, _, _ := a.Issue(bob)

	r := req("GET", "/api/subscriptions/s1/export")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 403 {
		t.Errorf("a client read a subscription's origin: got %d, want 403", got)
	}
	if got := serve(s, req("GET", "/api/subscriptions/s1/export")).Code; got != 401 {
		t.Errorf("a subscription's origin was reachable anonymously: got %d, want 401", got)
	}
}

// An unknown path must not be less protected than a known one. With levels
// declared per route, anything unlisted is admin — so adding a handler and
// forgetting its entry fails loudly for the operator instead of quietly for
// everyone else.
func TestUnknownPathsRequireAdmin(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	tok, _, _ := a.Issue(bob)

	r := req("GET", "/api/something-nobody-declared")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 403 {
		t.Fatalf("an undeclared path was reachable by a client: got %d, want 403", got)
	}
	if got := serve(s, req("GET", "/api/something-nobody-declared")).Code; got != 401 {
		t.Fatalf("an undeclared path was reachable anonymously: got %d, want 401", got)
	}
}

// The table and the routes have to be the same set. A pattern with no declared
// level, or a declared level for a pattern nobody serves, means the matrix in
// access.go has stopped describing the server — which is how the four holes above
// survived being "a table, not scattered checks".
func TestEveryRouteHasADeclaredLevelAndViceVersa(t *testing.T) {
	// A bare Server is enough: registerRoutes only needs to hand the mux method
	// values, and taking a method value does not call it.
	(&Server{}).registerRoutes(http.NewServeMux())

	served := servedPatterns()
	declared := routeLevels()

	for p := range served {
		if _, ok := declared[p]; !ok {
			t.Errorf("route %q is served but declares no access level", p)
		}
	}
	for p := range declared {
		if _, ok := served[p]; !ok {
			t.Errorf("access level declared for %q, which no route serves", p)
		}
	}
}
