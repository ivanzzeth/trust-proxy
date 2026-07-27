package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/authn"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/users"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Changing a password has to end the sessions that password opened.
//
// authenticate re-reads the account on every request and honours Disabled and a
// changed Role, so a disabled or demoted account loses access immediately. Nothing
// bound the token to the password: SetPassword left every issued JWT valid for the
// rest of its 12-hour life. So the advice everybody gives for a stolen session —
// change your password — did nothing here, and the only real revocation was
// disabling the account or deleting jwt-secret (which logs out everyone).
func TestChangingThePasswordEndsExistingSessions(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	admin, err := us.Create("admin", "admin-password-long", users.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := a.Issue(admin)
	if err != nil {
		t.Fatal(err)
	}

	authed := func() int {
		r := req("GET", "/api/status")
		r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
		return serve(s, r).Code
	}
	if got := authed(); got != 200 {
		t.Fatalf("the session does not work to begin with: %d", got)
	}

	if err := us.SetPassword(admin.ID, "a-different-password-long"); err != nil {
		t.Fatal(err)
	}
	if got := authed(); got != 401 {
		t.Fatalf("the old session still works after a password change: %d — so 'change your "+
			"password' is not a way to end a stolen session", got)
	}

	// A session issued after the change works, or this is a lockout rather than a
	// revocation.
	fresh, ok := us.ByID(admin.ID)
	if !ok {
		t.Fatal("account vanished")
	}
	tok, _, err = a.Issue(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if got := authed(); got != 200 {
		t.Fatalf("a session issued after the password change does not work: %d", got)
	}
}

// Only that account's sessions. Rotating one person's password must not log out
// everybody, or admins will avoid doing it.
func TestAPasswordChangeDoesNotEndOtherPeoplesSessions(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	admin, _ := us.Create("admin", "admin-password-long", users.RoleAdmin)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	bobTok, _, _ := a.Issue(bob)

	if err := us.SetPassword(admin.ID, "admin-password-changed"); err != nil {
		t.Fatal(err)
	}
	r := req("GET", "/api/status")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: bobTok})
	if got := serve(s, r).Code; got != 200 {
		t.Fatalf("bob was logged out by an unrelated password change: %d", got)
	}
}

// An API key is a separate credential with its own lifecycle, deliberately: it is
// how the CLI works unattended, and rotating a human password must not silently
// break every script.
func TestAPasswordChangeLeavesAPIKeysAlone(t *testing.T) {
	s, us, _, _ := newAuthServer(t)
	admin, _ := us.Create("admin", "admin-password-long", users.RoleAdmin)
	created, err := us.CreateAPIKey(admin.ID, "cli", 0)
	if err != nil {
		t.Fatal(err)
	}
	key := created.Key
	if err := us.SetPassword(admin.ID, "admin-password-changed"); err != nil {
		t.Fatal(err)
	}
	r := req("GET", "/api/status")
	r.Header.Set("Authorization", "Bearer "+key)
	if got := serve(s, r).Code; got != 200 {
		t.Fatalf("an API key stopped working because a password changed: %d", got)
	}
}

// Changing your own password requires proving you know the current one.
//
// Without that, a stolen session is not merely a session: it is a takeover, because
// the thief can set a password of their own and lock the owner out of an account
// they still own.
func TestSelfServicePasswordChangeRequiresTheCurrentPassword(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	_, _ = us.Create("admin", "admin-password-long", users.RoleAdmin)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	tok, _, _ := a.Issue(bob)

	// The real handler, not serve(): serve only runs the middleware and answers from
	// a stub, so a test built on it reports 200 for a request that never reached any
	// code under test. Worth stating because the first version of this test did
	// exactly that and looked like it was measuring something.
	patch := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPatch, "/api/users/"+bob.ID, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.SetPathValue("id", bob.ID)
		r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
		rec := httptest.NewRecorder()
		s.handlePatchUser(rec, r)
		return rec
	}
	if rec := patch(`{"password":"brand-new-password"}`); rec.Code == 200 {
		t.Fatalf("a session changed its own password without proving the old one: %d %s",
			rec.Code, rec.Body.String())
	}
	if rec := patch(`{"current_password":"wrong-password-long","password":"brand-new-password"}`); rec.Code == 200 {
		t.Fatalf("a wrong current password was accepted: %d", rec.Code)
	}
	rec := patch(`{"current_password":"bob-password-long","password":"brand-new-password"}`)
	if rec.Code != 200 {
		t.Fatalf("the correct current password was refused: %d %s", rec.Code, rec.Body.String())
	}
	// The caller keeps a working session: the change revokes every session that
	// password opened, including this one, so a fresh cookie comes back with it.
	// Being logged out of the browser you just typed your new password into is the
	// reason people put off changing it.
	var fresh string
	for _, c := range rec.Result().Cookies() {
		if c.Name == authn.CookieName {
			fresh = c.Value
		}
	}
	if fresh == "" {
		t.Fatal("no new session cookie after changing your own password: the caller is logged out")
	}
	r := req("GET", "/api/status")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: fresh})
	if got := serve(s, r).Code; got != 200 {
		t.Fatalf("the re-issued session does not work: %d", got)
	}
	// And the one from before the change is dead.
	r = req("GET", "/api/status")
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
	if got := serve(s, r).Code; got != 401 {
		t.Fatalf("the pre-change session still works: %d", got)
	}
}

// An admin resetting somebody else's password does not know it, and requiring it
// would make a reset impossible — which is the one thing a reset is for. The reset
// still has to end that account's sessions.
func TestAnAdminCanResetAnotherAccountWithoutTheOldPassword(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	admin, _ := us.Create("admin", "admin-password-long", users.RoleAdmin)
	bob, _ := us.Create("bob", "bob-password-long", users.RoleClient)
	adminTok, _, _ := a.Issue(admin)
	bobTok, _, _ := a.Issue(bob)

	// Bob's session works first, or the assertion after the reset proves nothing.
	check := func(tok string) int {
		r := req("GET", "/api/status")
		r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
		return serve(s, r).Code
	}
	if got := check(bobTok); got != 200 {
		t.Fatalf("bob's session does not work to begin with: %d", got)
	}

	r := httptest.NewRequest(http.MethodPatch, "/api/users/"+bob.ID,
		strings.NewReader(`{"password":"reset-by-the-admin"}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.SetPathValue("id", bob.ID)
	r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: adminTok})
	rec := httptest.NewRecorder()
	s.handlePatchUser(rec, r)
	if rec.Code != 200 {
		t.Fatalf("an admin could not reset another account's password: %d %s", rec.Code, rec.Body.String())
	}
	if got := check(bobTok); got != 401 {
		t.Fatalf("bob's session survived an admin password reset: %d", got)
	}
}

// Denying a permit request must remove only that request, and must re-apply.
//
// handleDenyPermitRequest called cr.Remove(id) without the PackRequestPrefix check
// its sibling approve does, so an id naming an ordinary custom rule deleted that
// rule instead — and it never called the applier, so the store and the data plane
// diverged: whatever was removed stayed in force until the next rebuild for any
// other reason. "Revoked" read as done and was not.
func TestDenyingAPermitRequestOnlyTouchesRequests(t *testing.T) {
	dir := t.TempDir()
	cr, err := customrules.NewStore(filepath.Join(dir, "customrules.json"))
	if err != nil {
		t.Fatal(err)
	}
	applier := &countingCRApplier{}
	s := &Server{cr: cr, crApplier: applier}

	yes := true
	if _, err := cr.Add(apitypes.CustomRule{
		Match: "domain", Value: "ordinary.example", Permit: &yes, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := cr.Add(apitypes.CustomRule{
		Match: "domain", Value: "asked-for.example", Permit: &yes, Enabled: false,
		Pack: apitypes.PackRequestPrefix + "bob",
	}); err != nil {
		t.Fatal(err)
	}
	ordinaryID := ruleIDFor(t, cr, "ordinary.example")
	pendingID := ruleIDFor(t, cr, "asked-for.example")

	deny := func(id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodDelete, "/api/permit-requests/"+id, nil)
		r.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.handleDenyPermitRequest(rec, r)
		return rec
	}

	if rec := deny(ordinaryID); rec.Code == http.StatusOK {
		t.Fatalf("denying a 'request' deleted an ordinary enabled custom rule: %d %s",
			rec.Code, rec.Body.String())
	}
	if !hasRule(cr, ordinaryID) {
		t.Fatal("the ordinary rule is gone — an admin denying a request can delete arbitrary policy")
	}

	if rec := deny(pendingID); rec.Code != http.StatusOK {
		t.Fatalf("denying a real request failed: %d %s", rec.Code, rec.Body.String())
	}
	if hasRule(cr, pendingID) {
		t.Fatal("the request was not removed")
	}
	if applier.calls == 0 {
		t.Fatal("the policy was not re-applied, so the store and the data plane disagree and " +
			"the rule stays in force until something else rebuilds")
	}
}

func ruleIDFor(t *testing.T, cr *customrules.Store, value string) string {
	t.Helper()
	for _, r := range cr.Get().Rules {
		if r.Value == value {
			return r.ID
		}
	}
	t.Fatalf("no rule for %q", value)
	return ""
}

func hasRule(cr *customrules.Store, id string) bool {
	for _, r := range cr.Get().Rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

type countingCRApplier struct{ calls int }

func (c *countingCRApplier) SetCustomRules(customrules.Rules) error { c.calls++; return nil }
