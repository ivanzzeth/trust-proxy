package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/authn"
	"github.com/ivanzzeth/trust-proxy/internal/users"
)

// Settings → System shows which build is running and where its files are, and
// /api/status is where it reads them. Both are admin-only facts: an exact
// version handed to any account that can reach the port is free targeting
// information, and the data directory names a path a client has no business
// knowing. /api/health carries the same version for the desktop shell, but only
// over loopback — this is the authenticated equivalent, not a second copy of
// the same permission.
func TestStatusReportsInstallFactsToAdminsOnly(t *testing.T) {
	s, us, a, dir := newAuthServer(t)
	s.version = "v9.9.9-test"

	admin, err := us.Create("admin", "admin-password-long", users.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	client, err := us.Create("bob", "bob-password-long", users.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	adminTok, _, _ := a.Issue(admin)
	clientTok, _, _ := a.Issue(client)

	get := func(tok string) map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		if tok != "" {
			r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
		}
		rec := httptest.NewRecorder()
		s.handleStatus(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d", rec.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	adminBody := get(adminTok)
	if adminBody["version"] != "v9.9.9-test" {
		t.Errorf("admin version: got %v, want v9.9.9-test", adminBody["version"])
	}
	if adminBody["data_dir"] != dir {
		t.Errorf("admin data_dir: got %v, want %q", adminBody["data_dir"], dir)
	}

	// A client reaches /api/status (it is accessUser) and must still not learn
	// either fact. Absent, not blank: a "" would read as "this gateway has no
	// data directory" rather than "not yours to see".
	clientBody := get(clientTok)
	if _, ok := clientBody["version"]; ok {
		t.Errorf("client saw version: %v", clientBody["version"])
	}
	if _, ok := clientBody["data_dir"]; ok {
		t.Errorf("client saw data_dir: %v", clientBody["data_dir"])
	}
}
