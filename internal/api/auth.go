package api

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/authn"
	"github.com/ivanzzeth/trust-proxy/internal/users"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Authentication and authorization for /api/*.
//
// The reason this exists: once the data plane runs as a privileged system
// service, an open loopback API is a privilege-escalation path — any unprivileged
// local process could turn off default-deny, and getting itself out is exactly
// what an implant wants.
//
// Three ways to authenticate, in the order they are tried:
//
//  1. an **API key** (`Authorization: Bearer tp_…` or `X-API-Key`) — the CLI and
//     scripts;
//  2. a **session JWT** (httpOnly cookie, or a bearer for scripted logins) — the
//     console;
//  3. the legacy **--api-token** static string, kept so existing probe/fleet
//     deployments keep working.
//
// Authorization is a table, not scattered checks: `requirement()` maps a request
// to public / authenticated / admin, so the whole policy can be read in one place
// and tested as a matrix.

// access levels, lowest first.
type access int

const (
	accessPublic access = iota // no identity needed
	accessUser                 // any logged-in account
	accessAdmin                // admin only
)

// readOnlyForUsers are the GET-able prefixes a non-admin may see: the
// observability surface. Everything else — policy, mode, users, fleet — is admin.
//
// A plain user can watch, and cannot change what the gateway enforces.
var readOnlyForUsers = []string{
	"/api/health", "/api/status", "/api/connections", "/api/traffic",
	"/api/events", "/api/detections", "/api/history", "/api/logs",
	"/api/dns-queries", "/api/netcheck", "/api/fingerprints", "/api/rules",
	"/api/proxies", "/api/effective-rules", "/api/auth/me", "/api/auth/state",
}

// publicPaths need no identity at all. Deliberately tiny: everything here is
// reachable by anyone who can reach the port.
var publicPaths = []string{
	"/api/health",         // liveness, used by the desktop shell before login
	"/api/auth/state",     // "do I need to bootstrap, may I register?"
	"/api/auth/bootstrap", // create the first admin (guarded separately, see below)
	"/api/auth/login",
	"/api/auth/logout",
	"/api/auth/register", // refused by the store unless an admin opened it
}

// requirement returns the access level a request needs.
func requirement(r *http.Request) access {
	p := path0(r.URL.Path)
	for _, pub := range publicPaths {
		if p == pub {
			return accessPublic
		}
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		for _, ro := range readOnlyForUsers {
			if p == ro || strings.HasPrefix(p, ro+"/") {
				return accessUser
			}
		}
	}
	return accessAdmin
}

// path0 strips the /api/nodes/{id} reverse-proxy prefix so a request forwarded to
// a remote gateway is judged by what it actually asks for, not by the prefix.
func path0(p string) string {
	if !strings.HasPrefix(p, "/api/nodes/") {
		return p
	}
	rest := strings.TrimPrefix(p, "/api/nodes/")
	if i := strings.Index(rest, "/"); i >= 0 {
		return "/api" + rest[i:]
	}
	return p
}

// withAuth authenticates and authorizes /api/*; console assets stay open so the
// login page itself can load.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		need := requirement(r)

		// A same-origin console plus a SameSite=Strict cookie already stops most
		// cross-site abuse; rejecting a foreign Origin on mutations closes the rest
		// (a page on another site scripting our loopback API).
		if need != accessPublic && isMutation(r.Method) && !s.originOK(r) {
			writeErr(w, http.StatusForbidden, "cross-origin request refused")
			return
		}

		user, err := s.authenticate(r)
		if need == accessPublic {
			next.ServeHTTP(w, r)
			return
		}
		if err != nil || user == nil {
			// 401 with a hint the console can act on: an empty registry means the
			// browser should show "create the first admin", not "log in".
			if s.users != nil && s.users.Empty() {
				writeErr(w, http.StatusUnauthorized, "no accounts yet: create the first admin")
				return
			}
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if need == accessAdmin && user.Role != users.RoleAdmin {
			writeErr(w, http.StatusForbidden, "this action requires an administrator")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isMutation(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// originOK accepts a missing Origin (curl, the CLI, the desktop shell) and
// otherwise requires it to match the host we were reached on.
func (s *Server) originOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// authenticate resolves the caller, or returns nil when anonymous.
func (s *Server) authenticate(r *http.Request) (*apitypes.User, error) {
	// 1. API key.
	if key := apiKeyFrom(r); key != "" && s.users != nil {
		u, err := s.users.AuthenticateAPIKey(key)
		if err != nil {
			return nil, err
		}
		return &u, nil
	}
	// 2. Legacy static token: full admin, for probes configured with --api-token.
	//
	// Checked before the session, because both arrive as `Authorization: Bearer …`
	// and a static token would otherwise be swallowed by the JWT parser as a
	// malformed session (measured: it returned 401 instead of falling through).
	if s.token != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1 {
			return &apitypes.User{ID: "static-token", Username: "api-token", Role: users.RoleAdmin}, nil
		}
	}
	// 3. Session JWT.
	if tok := authn.SessionToken(r); tok != "" && s.authn != nil {
		claims, err := s.authn.Verify(tok)
		if err == nil && s.users != nil {
			// Re-read the account: a token outlives a role change or a disable, and
			// the stored record is the truth.
			if u, ok := s.users.ByID(claims.Subject); ok && !u.Disabled {
				return &u, nil
			}
			return nil, authn.ErrRevoked
		}
		if err != nil {
			return nil, err
		}
	}
	// No accounts and no token configured: an unclaimed gateway is open, which is
	// what makes bootstrap possible at all. The console pushes you to create the
	// first admin immediately, and `serve` says so in the log.
	if s.users == nil || (s.users.Empty() && s.token == "") {
		return &apitypes.User{ID: "unclaimed", Username: "unclaimed", Role: users.RoleAdmin}, nil
	}
	return nil, nil
}

func apiKeyFrom(r *http.Request) string {
	if k := r.Header.Get("X-API-Key"); strings.HasPrefix(k, users.KeyPrefix) {
		return k
	}
	if h := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); strings.HasPrefix(h, users.KeyPrefix) {
		return h
	}
	return ""
}

// caller returns the authenticated account for a handler (nil when anonymous).
func (s *Server) caller(r *http.Request) *apitypes.User {
	u, _ := s.authenticate(r)
	return u
}

// ---- handlers ------------------------------------------------------------

func (s *Server) handleAuthState(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	st := apitypes.AuthState{
		NeedsBootstrap:    s.users.Empty(),
		AllowRegistration: s.users.Settings().AllowRegistration,
	}
	if u, err := s.authenticate(r); err == nil && u != nil && u.ID != "unclaimed" {
		st.Authenticated = true
		st.User = u
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	u := s.caller(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// handleBootstrap creates the first admin.
//
// Allowed only while the registry is empty. From loopback that is enough — you
// are on the machine. Over the network it additionally demands the one-time code
// `serve` printed, because otherwise whoever reaches the port first owns the
// gateway.
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	if !s.users.Empty() {
		writeErr(w, http.StatusConflict, "already bootstrapped: log in, or have an admin create your account")
		return
	}
	var req struct {
		apitypes.LoginRequest
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !isLoopback(r.RemoteAddr) {
		if s.authn == nil || !s.authn.CheckBootstrapCode(req.Code) {
			writeErr(w, http.StatusForbidden,
				"remote bootstrap needs the one-time code from the gateway's log (or run `trust-proxy user add --admin` on the machine itself)")
			return
		}
	}
	u, err := s.users.Create(req.Username, req.Password, users.RoleAdmin)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.authn != nil {
		s.authn.ClearBootstrapCode(s.dataDir)
	}
	s.issueSession(w, u)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.users == nil || s.authn == nil {
		writeErr(w, http.StatusServiceUnavailable, "authentication not available")
		return
	}
	var req apitypes.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	u, err := s.users.Authenticate(req.Username, req.Password)
	if err != nil {
		// One message for every failure: which half was wrong is not the caller's
		// business.
		writeErr(w, http.StatusUnauthorized, users.ErrInvalidCredentials.Error())
		return
	}
	s.issueSession(w, u)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.authn != nil {
		s.authn.ClearCookie(w)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	var req apitypes.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	u, err := s.users.Register(req.Username, req.Password)
	if err != nil {
		code := http.StatusBadRequest
		if err == users.ErrRegistrationClosed {
			code = http.StatusForbidden
		}
		writeErr(w, code, err.Error())
		return
	}
	s.issueSession(w, u)
}

func (s *Server) issueSession(w http.ResponseWriter, u apitypes.User) {
	if s.authn == nil {
		writeJSON(w, http.StatusOK, apitypes.Session{User: u})
		return
	}
	token, exp, err := s.authn.Issue(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.authn.SetCookie(w, token, exp)
	writeJSON(w, http.StatusOK, apitypes.Session{User: u, ExpiresAt: exp.UTC().Format(time.RFC3339)})
}

// handleGetAuthSettings / handleSetAuthSettings own the registration switch.
func (s *Server) handleGetAuthSettings(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	writeJSON(w, http.StatusOK, apitypes.AuthSettings{AllowRegistration: s.users.Settings().AllowRegistration})
}

func (s *Server) handleSetAuthSettings(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "user registry not available")
		return
	}
	var req apitypes.AuthSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.users.SetAllowRegistration(req.AllowRegistration); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, apitypes.AuthSettings{AllowRegistration: req.AllowRegistration})
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
