package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/authn"
	"github.com/ivanzzeth/trust-proxy/internal/users"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
	"github.com/ivanzzeth/trust-proxy/pkg/clash"
)

// The authorization policy is a table, so it gets tested as one. What matters is
// not that a handler works but that the wrong caller cannot reach it: a
// non-admin must not be able to switch off default-deny, and an anonymous caller
// must not be able to do anything at all once the gateway is claimed.

func newAuthServer(t *testing.T) (*Server, *users.Store, *authn.Authn, string) {
	t.Helper()
	dir := t.TempDir()
	us, err := users.NewStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := authn.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{users: us, authn: a, dataDir: dir}, us, a, dir
}

// serve runs one request through the auth middleware plus a handler that just
// says "reached", so the status code is entirely the middleware's verdict.
func serve(s *Server, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"reached": "yes"})
	})
	s.withAuth(inner).ServeHTTP(rec, r)
	return rec
}

func req(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	r.RemoteAddr = "127.0.0.1:1234"
	return r
}

func TestAccessMatrix(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	admin, err := us.Create("admin", "admin-password-long", users.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := us.Create("bob", "bob-password-long", users.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	adminTok, _, _ := a.Issue(admin)
	plainTok, _, _ := a.Issue(plain)

	type want struct{ anon, user, adm int }
	cases := []struct {
		method, path string
		want         want
	}{
		// Public: the console must be able to ask what to do before anyone logs in.
		{"GET", "/api/health", want{200, 200, 200}},
		{"GET", "/api/auth/state", want{200, 200, 200}},
		{"POST", "/api/auth/login", want{200, 200, 200}},

		// Observability: any account may look.
		{"GET", "/api/status", want{401, 200, 200}},
		{"GET", "/api/connections", want{401, 200, 200}},
		{"GET", "/api/history", want{401, 200, 200}},
		{"GET", "/api/detections", want{401, 200, 200}},

		// Policy: admin only. These are the ones that decide what leaves the network.
		{"POST", "/api/whitelist", want{401, 403, 200}},
		{"DELETE", "/api/whitelist", want{401, 403, 200}},
		{"POST", "/api/mode", want{401, 403, 200}},
		{"PUT", "/api/clash-mode", want{401, 403, 200}},
		{"PUT", "/api/posture", want{401, 403, 200}},
		{"POST", "/api/customrules", want{401, 403, 200}},
		{"PUT", "/api/dns", want{401, 403, 200}},
		{"POST", "/api/subscriptions", want{401, 403, 200}},
		{"DELETE", "/api/connections/abc", want{401, 403, 200}},

		// A read of the policy surface is still admin: it exposes what is permitted.
		{"GET", "/api/whitelist", want{401, 403, 200}},
		{"GET", "/api/users", want{401, 403, 200}},

		// User administration and the fleet: admin only.
		{"POST", "/api/users", want{401, 403, 200}},
		{"PATCH", "/api/users/u1", want{401, 403, 200}},
		{"DELETE", "/api/users/u1", want{401, 403, 200}},
		{"PUT", "/api/auth/settings", want{401, 403, 200}},
		{"POST", "/api/nodes", want{401, 403, 200}},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			if got := serve(s, req(c.method, c.path)).Code; got != c.want.anon {
				t.Errorf("anonymous: got %d, want %d", got, c.want.anon)
			}
			r := req(c.method, c.path)
			r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: plainTok})
			if got := serve(s, r).Code; got != c.want.user {
				t.Errorf("role=user: got %d, want %d", got, c.want.user)
			}
			r = req(c.method, c.path)
			r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: adminTok})
			if got := serve(s, r).Code; got != c.want.adm {
				t.Errorf("role=admin: got %d, want %d", got, c.want.adm)
			}
		})
	}
}

// An API key is the CLI's credential and must carry its owner's role.
func TestAPIKeyAuthenticatesWithTheOwnersRole(t *testing.T) {
	s, us, _, _ := newAuthServer(t)
	admin, _ := us.Create("admin", "admin-password-long", users.RoleAdmin)
	plain, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	adminKey, _ := us.CreateAPIKey(admin.ID, "cli", 0)
	plainKey, _ := us.CreateAPIKey(plain.ID, "cli", 0)

	for _, tc := range []struct {
		name, key  string
		header     string
		wantPolicy int
	}{
		{"admin key, bearer", adminKey.Key, "Authorization", 200},
		{"admin key, x-api-key", adminKey.Key, "X-API-Key", 200},
		{"user key", plainKey.Key, "X-API-Key", 403},
		{"bogus key", users.KeyPrefix + "nope", "X-API-Key", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := req("POST", "/api/mode")
			if tc.header == "Authorization" {
				r.Header.Set("Authorization", "Bearer "+tc.key)
			} else {
				r.Header.Set(tc.header, tc.key)
			}
			if got := serve(s, r).Code; got != tc.wantPolicy {
				t.Fatalf("got %d, want %d", got, tc.wantPolicy)
			}
		})
	}
}

// A session must stop working the moment the account behind it is disabled — a
// JWT outlives the account, so the middleware re-reads the record.
func TestDisabledAccountLosesItsSessionImmediately(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	tok, _, _ := a.Issue(bob)

	r := req("GET", "/api/status")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 200 {
		t.Fatalf("valid session: got %d", got)
	}
	if err := us.SetDisabled(bob.ID, true); err != nil {
		t.Fatal(err)
	}
	r = req("GET", "/api/status")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 401 {
		t.Fatalf("disabled account still authenticated: got %d", got)
	}
}

// Demoting an admin must take effect on their existing session too, not at the
// next login.
func TestRoleChangeAppliesToLiveSessions(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	first, _ := us.Create("admin", "admin-password-long", users.RoleAdmin)
	second, _ := us.Create("admin2", "second-password-long", users.RoleAdmin)
	tok, _, _ := a.Issue(second)

	r := req("POST", "/api/mode")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 200 {
		t.Fatalf("admin: got %d", got)
	}
	if err := us.SetRole(second.ID, users.RoleClient); err != nil {
		t.Fatal(err)
	}
	r = req("POST", "/api/mode")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 403 {
		t.Fatalf("demoted admin still admin: got %d", got)
	}
	_ = first
}

// An unclaimed gateway (no accounts, no --api-token) has to be open, or it could
// never be set up. It must stop being open the instant the first admin exists.
func TestUnclaimedGatewayIsOpenThenClosed(t *testing.T) {
	s, us, _, _ := newAuthServer(t)
	if got := serve(s, req("POST", "/api/mode")).Code; got != 200 {
		t.Fatalf("unclaimed gateway should be usable: got %d", got)
	}
	if _, err := us.Create("admin", "admin-password-long", users.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	rec := serve(s, req("POST", "/api/mode"))
	if rec.Code != 401 {
		t.Fatalf("claimed gateway still open: got %d", rec.Code)
	}
}

// The legacy --api-token keeps existing probe/fleet deployments working, with
// admin rights, and nothing else must be accepted in its place.
func TestLegacyStaticToken(t *testing.T) {
	s, _, _, _ := newAuthServer(t)
	s.token = "s3cret"
	r := req("POST", "/api/mode")
	r.Header.Set("Authorization", "Bearer s3cret")
	if got := serve(s, r).Code; got != 200 {
		t.Fatalf("static token rejected: got %d", got)
	}
	r = req("POST", "/api/mode")
	r.Header.Set("Authorization", "Bearer wrong")
	if got := serve(s, r).Code; got != 401 {
		t.Fatalf("wrong static token accepted: got %d", got)
	}
	// With a token configured, anonymous is not open even with no accounts.
	if got := serve(s, req("POST", "/api/mode")).Code; got != 401 {
		t.Fatalf("anonymous accepted while a token is configured: got %d", got)
	}
}

// A page on another site must not be able to script our loopback API through the
// browser's cookie.
func TestCrossOriginMutationsAreRefused(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	admin, _ := us.Create("admin", "admin-password-long", users.RoleAdmin)
	tok, _, _ := a.Issue(admin)

	r := req("POST", "/api/mode")
	r.Host = "127.0.0.1:21585"
	r.Header.Set("Origin", "http://evil.example")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 403 {
		t.Fatalf("cross-origin mutation: got %d, want 403", got)
	}
	// Same origin is fine…
	r = req("POST", "/api/mode")
	r.Host = "127.0.0.1:21585"
	r.Header.Set("Origin", "http://127.0.0.1:21585")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 200 {
		t.Fatalf("same-origin mutation: got %d", got)
	}
	// …and a GET is not blocked by it (no state change, and the CLI sends no Origin).
	r = req("GET", "/api/status")
	r.Header.Set("Origin", "http://evil.example")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 200 {
		t.Fatalf("cross-origin GET: got %d", got)
	}
}

// The /api/nodes/{id}/… reverse proxy must be judged by what the forwarded
// request asks for, or a plain user could reach an admin endpoint on a remote
// gateway through the prefix.
func TestNodeProxyPrefixIsJudgedByTheForwardedPath(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	tok, _, _ := a.Issue(bob)

	r := req("POST", "/api/nodes/n1/mode")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 403 {
		t.Fatalf("proxied admin call by a plain user: got %d, want 403", got)
	}
	r = req("GET", "/api/nodes/n1/status")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 200 {
		t.Fatalf("proxied read by a plain user: got %d, want 200", got)
	}
}

// Bootstrap: free from loopback (you are on the machine), code-gated from off-box
// (otherwise whoever reaches the port first owns the gateway).
func TestBootstrapGuards(t *testing.T) {
	s, us, a, dir := newAuthServer(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/bootstrap",
		strings.NewReader(`{"username":"remote","password":"remote-password-long"}`))
	r.RemoteAddr = "192.168.1.50:5000"
	s.handleBootstrap(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote bootstrap without a code: got %d, want 403", rec.Code)
	}

	code, err := a.BootstrapCode(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/api/auth/bootstrap",
		strings.NewReader(`{"username":"remote","password":"remote-password-long","code":"`+code+`"}`))
	r.RemoteAddr = "192.168.1.50:5000"
	s.handleBootstrap(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("remote bootstrap with the code: got %d (%s)", rec.Code, rec.Body)
	}
	var sess apitypes.Session
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
		t.Fatal(err)
	}
	if sess.User.Role != users.RoleAdmin {
		t.Fatalf("bootstrapped role = %q, want admin", sess.User.Role)
	}
	// A session cookie comes back, so the console is logged in straight away.
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("bootstrap did not set a session cookie")
	}
	// And it cannot happen twice.
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/api/auth/bootstrap",
		strings.NewReader(`{"username":"second","password":"second-password-long"}`))
	r.RemoteAddr = "127.0.0.1:1"
	s.handleBootstrap(rec, r)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second bootstrap: got %d, want 409", rec.Code)
	}
	_ = us
}

func TestLoopbackBootstrapNeedsNoCode(t *testing.T) {
	s, _, _, _ := newAuthServer(t)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/bootstrap",
		strings.NewReader(`{"username":"alice","password":"alice-password-long"}`))
	r.RemoteAddr = "127.0.0.1:9999"
	s.handleBootstrap(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback bootstrap: got %d (%s)", rec.Code, rec.Body)
	}
}

// Login must not tell a caller which half of the credential was wrong.
func TestLoginFailureIsOpaque(t *testing.T) {
	s, us, _, _ := newAuthServer(t)
	_, _ = us.Create("alice", "alice-password-long", users.RoleAdmin)

	body := func(u, p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleLogin(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login",
			strings.NewReader(`{"username":"`+u+`","password":"`+p+`"}`)))
		return rec
	}
	unknown := body("nobody", "alice-password-long")
	wrongPw := body("alice", "not-the-password")
	if unknown.Code != 401 || wrongPw.Code != 401 {
		t.Fatalf("codes: %d %d", unknown.Code, wrongPw.Code)
	}
	if unknown.Body.String() != wrongPw.Body.String() {
		t.Fatalf("responses differ and leak account existence:\n%s\n%s", unknown.Body, wrongPw.Body)
	}
	if ok := body("alice", "alice-password-long"); ok.Code != 200 {
		t.Fatalf("valid login: got %d (%s)", ok.Code, ok.Body)
	}
}

// Registration is closed by default; opening it is an admin action and produces
// plain users only.
func TestRegistrationFlow(t *testing.T) {
	s, us, _, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)

	register := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleRegister(rec, httptest.NewRequest(http.MethodPost, "/api/auth/register",
			strings.NewReader(`{"username":"carol","password":"carol-password-long"}`)))
		return rec
	}
	if rec := register(); rec.Code != http.StatusForbidden {
		t.Fatalf("registration closed: got %d, want 403", rec.Code)
	}
	if err := us.SetAllowRegistration(true); err != nil {
		t.Fatal(err)
	}
	rec := register()
	if rec.Code != http.StatusOK {
		t.Fatalf("registration open: got %d (%s)", rec.Code, rec.Body)
	}
	var sess apitypes.Session
	_ = json.Unmarshal(rec.Body.Bytes(), &sess)
	if sess.User.Role != users.RoleClient {
		t.Fatalf("self-registered role = %q, want user", sess.User.Role)
	}
}

// A client sees its own traffic and only its own. On a shared gateway the
// alternative is that every user can watch every other user's destinations —
// the gateway would leak the very thing it exists to control.
func TestObservabilityIsScopedToTheCaller(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	admin, _ := us.Create("admin", "admin-password-long", users.RoleAdmin)
	alice, _ := us.Create("alice", "alice-password-long", users.RoleClient)

	snap := clash.Connections{
		UploadTotal: 300, DownloadTotal: 3000,
		Connections: []clash.Connection{
			{ID: "1", Upload: 100, Download: 1000, Metadata: clash.Metadata{Host: "mine.example", User: "alice"}},
			{ID: "2", Upload: 200, Download: 2000, Metadata: clash.Metadata{Host: "theirs.example", User: "bob"}},
		},
	}
	// A client: only its own rows, and the totals recomputed to match.
	got := scopeConnections(snap, "alice")
	if len(got.Connections) != 1 || got.Connections[0].Metadata.Host != "mine.example" {
		t.Fatalf("scoped connections = %+v", got.Connections)
	}
	if got.UploadTotal != 100 || got.DownloadTotal != 1000 {
		t.Fatalf("totals still describe the whole gateway: up=%d down=%d", got.UploadTotal, got.DownloadTotal)
	}
	// An admin: everything, untouched.
	if all := scopeConnections(snap, ""); len(all.Connections) != 2 || all.UploadTotal != 300 {
		t.Fatalf("admin view was filtered: %+v", all)
	}

	// Case-insensitive, since usernames are matched that way everywhere else.
	if len(scopeConnections(snap, "ALICE").Connections) != 1 {
		t.Fatal("username matching must be case-insensitive")
	}

	// And the scope comes from the session, not from the request.
	aliceTok, _, _ := a.Issue(alice)
	r := req("GET", "/api/connections")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: aliceTok})
	if scope := s.scopeUser(r); scope != "alice" {
		t.Fatalf("scopeUser = %q, want alice", scope)
	}
	adminTok, _, _ := a.Issue(admin)
	r = req("GET", "/api/connections")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: adminTok})
	if scope := s.scopeUser(r); scope != "" {
		t.Fatalf("admin scope = %q, want unrestricted", scope)
	}
}

// Self-service exists so a client can change its own password without an admin —
// and stops exactly there. Being your own account is not the same as being an
// admin of it.
func TestSelfServiceCannotEscalate(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)
	alice, _ := us.Create("alice", "alice-password-long", users.RoleClient)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	tok, _, _ := a.Issue(alice)

	withSession := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1"
		r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
		rec := httptest.NewRecorder()
		s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, rr *http.Request) {
			rr.SetPathValue("id", strings.TrimPrefix(strings.Split(rr.URL.Path, "/apikeys")[0], "/api/users/"))
			s.handlePatchUser(w, rr)
		})).ServeHTTP(rec, r)
		return rec
	}

	// Own password: allowed.
	if rec := withSession("PATCH", "/api/users/"+alice.ID, `{"password":"a-new-long-password"}`); rec.Code != 200 {
		t.Fatalf("own password change: got %d (%s)", rec.Code, rec.Body)
	}
	// Own role: refused — this is the escalation the middleware alone would miss.
	if rec := withSession("PATCH", "/api/users/"+alice.ID, `{"role":"admin"}`); rec.Code != 403 {
		t.Fatalf("self-promotion to admin: got %d, want 403 (%s)", rec.Code, rec.Body)
	}
	// Own proxy access: refused — that is a grant, not a self-service setting.
	if rec := withSession("PATCH", "/api/users/"+alice.ID, `{"proxy_password":"let-me-in"}`); rec.Code != 403 {
		t.Fatalf("self-granted proxy access: got %d, want 403 (%s)", rec.Code, rec.Body)
	}
	// Somebody else's account: refused by the middleware.
	if rec := withSession("PATCH", "/api/users/"+bob.ID, `{"password":"not-your-account"}`); rec.Code != 403 {
		t.Fatalf("patching another account: got %d, want 403 (%s)", rec.Code, rec.Body)
	}
}
