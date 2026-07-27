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

// The lists that used to live here — publicPaths and readOnlyForUsers — are gone.
// A prefix list answers questions about routes that did not exist when it was
// written: "/api/proxies" also granted /api/proxies/{name}/delay, and
// "/api/history" also granted the gateway-wide /api/history/stats. Levels are
// declared per route in access.go and resolved with the mux's own matching.

// selfService is what a client may do to its own account: change its password,
// rotate its own API keys. Judged against the authenticated identity in
// withAuth — the path alone cannot say whether {id} is you.
func isSelfService(r *http.Request) (id string, ok bool) {
	p := path0(r.URL.Path)
	if !strings.HasPrefix(p, "/api/users/") {
		return "", false
	}
	rest := strings.TrimPrefix(p, "/api/users/")
	id = rest
	if i := strings.Index(rest, "/"); i >= 0 {
		id, rest = rest[:i], rest[i:]
	} else {
		rest = ""
	}
	switch {
	case rest == "" && r.Method == http.MethodPatch: // own password (fields checked below)
		return id, true
	case strings.HasPrefix(rest, "/apikeys"): // own keys
		return id, true
	}
	return "", false
}

// requirement returns the access level a request needs, from the level its route
// declares in access.go.
//
// The only rule that is not a straight lookup is the reverse proxy. A forwarded
// request is judged by what it asks for — otherwise a client could reach an admin
// endpoint on a remote gateway through the prefix — but never below "logged in",
// because the relay injects the target gateway's stored token. Judging by the
// forwarded path *and* honouring a public level there is what turned this into an
// anonymous, credential-carrying relay onto every registered probe.
func requirement(r *http.Request) access {
	if target, ok := nodeProxyTarget(r.URL.Path); ok {
		need := levelOf(r.Method, target)
		if need < accessUser {
			need = accessUser
		}
		return need
	}
	return levelOf(r.Method, r.URL.Path)
}

// path0 strips the /api/nodes/{id} reverse-proxy prefix. Used by the checks that
// are about the *forwarded* request rather than the relay: self-service, and the
// per-caller scoping in the handlers.
func path0(p string) string {
	if target, ok := nodeProxyTarget(p); ok {
		return target
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
		//
		// Every mutation, including the public ones. This used to skip the check when
		// the level was public, which left POST /api/auth/{bootstrap,register,login,
		// logout} with no CSRF defence at all — and bootstrap on an unclaimed gateway
		// creates the first admin. Any page the operator visited could claim a
		// root-privileged gateway with credentials of the attacker's choosing, with no
		// need to read the response. A cookie is not the only thing worth protecting
		// here; the absence of one is.
		if isMutation(r.Method) && !s.originOK(r) {
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
			// One exception: your own account. A client has to be able to change its
			// own password and rotate its own API keys without an admin, and doing
			// that is not an administrative act.
			if id, ok := isSelfService(r); ok && id == user.ID {
				next.ServeHTTP(w, r)
				return
			}
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
	//
	// A key that does not authenticate must not end the attempt: a caller can
	// legitimately carry a stale TP_API_KEY *and* a fresh session — which is
	// exactly what `auth login` does, and it failed with "unauthorized" while
	// holding a valid session, because the dead key from a deleted account was
	// checked first and returned. The error is kept and only reported if nothing
	// else authenticates, so a genuinely bad key still says so.
	var keyErr error
	if key := apiKeyFrom(r); key != "" && s.users != nil {
		u, err := s.users.AuthenticateAPIKey(key)
		if err == nil {
			return &u, nil
		}
		keyErr = err
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
	if keyErr != nil {
		return nil, keyErr
	}
	// No accounts and no token configured: an unclaimed gateway has to accept some
	// unauthenticated call, or a fresh install could never be set up at all.
	//
	// **Only from loopback.** Being on the machine is the credential. Over the
	// network this was a hole and not a small one: the one-time claim code guards
	// `/api/auth/bootstrap` and nothing else, so a remote caller never had to
	// claim anything — it simply got this synthetic admin and drove the whole
	// policy API. An exposed, not-yet-claimed gateway belonged to whoever scanned
	// the port first. Off-loopback callers now get 401 for everything except
	// `/api/auth/state` and the code-gated bootstrap (see publicPaths).
	if s.users == nil || (s.users.Empty() && s.token == "") {
		if isLoopback(r.RemoteAddr) {
			return &apitypes.User{ID: "unclaimed", Username: "unclaimed", Role: users.RoleAdmin}, nil
		}
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
	st.NeedsBootstrapCode = st.NeedsBootstrap && !isLoopback(r.RemoteAddr)
	if s.authn != nil {
		// Lets a stored CLI credential tell "this gateway was reinstalled" apart
		// from "your key was revoked" — same 401, opposite advice.
		st.GatewayID = s.authn.GatewayID()
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
	// Passing the one-time code where the username goes is an easy mistake — the
	// CLI takes the username positionally, so a forgotten `--code` turns the code
	// into the account name, and it *works*: you end up permanently logging in as
	// "ObhbafOz__K_IruFbORgdg". The server can tell for certain, so it says so
	// instead of creating that account.
	if s.authn != nil && req.Username != "" && s.authn.CheckBootstrapCode(req.Username) {
		writeErr(w, http.StatusBadRequest,
			"that is the one-time claim code, not a username — it goes in --code (or the "+
				"code field in the browser). The username is the name you will log in with.")
		return
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

// handleMintTicket hands an authenticated caller a single-use token it can turn
// into a browser session by following a URL.
//
// The desktop shell is the caller: it holds the API key `install` wrote into its
// owner's home, and it needs the webview to arrive at the console already logged
// in. Passing the key into the page instead would leave an admin credential
// inside a web view for the life of the window.
func (s *Server) handleMintTicket(w http.ResponseWriter, r *http.Request) {
	u := s.caller(r)
	if u == nil || s.authn == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tok, err := s.authn.MintTicket(u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, apitypes.ConsoleTicket{
		Ticket:     tok,
		URL:        "http://" + r.Host + "/api/auth/ticket?t=" + url.QueryEscape(tok),
		ExpiresInS: int(authn.TicketTTL.Seconds()),
	})
}

// handleRedeemTicket turns a ticket into a session cookie and sends the browser
// to the console.
//
// A redirect rather than JSON: the caller here is a webview being pointed at a
// URL, and what it must end up with is a same-origin cookie plus the console.
func (s *Server) handleRedeemTicket(w http.ResponseWriter, r *http.Request) {
	if s.authn == nil || s.users == nil {
		writeErr(w, http.StatusServiceUnavailable, "authentication not available")
		return
	}
	id, ok := s.authn.RedeemTicket(r.URL.Query().Get("t"))
	if !ok {
		// Deliberately terse and deliberately not a login page: a bad ticket is
		// either expired or replayed, and both mean "ask the app again".
		writeErr(w, http.StatusForbidden, "this console ticket is expired or already used")
		return
	}
	u, found := s.users.ByID(id)
	if !found || u.Disabled {
		writeErr(w, http.StatusForbidden, "the account this ticket belongs to is gone or disabled")
		return
	}
	token, exp, err := s.authn.Issue(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.authn.SetCookie(w, token, exp)
	http.Redirect(w, r, "/", http.StatusFound)
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
