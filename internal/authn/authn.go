// Package authn issues and verifies the credentials the API accepts: a JWT for
// browser sessions, and (in internal/users) API keys for the CLI.
//
// Why a JWT and not a server-side session table: the gateway is a single process
// with no shared store, sessions are short-lived, and a signed token needs no
// lookup on the hot path. The cost is that revocation waits for expiry — so the
// TTL is hours, not weeks, and the signing key is regenerable (delete the file to
// invalidate every session at once).
//
// The token reaches the browser as an httpOnly cookie, never in localStorage:
// the console is a web page, and any XSS in it could read localStorage but not a
// cookie the script cannot see. SameSite=Strict then keeps another site from
// riding the cookie in a cross-site request.
package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// CookieName is the session cookie. Prefixed to avoid colliding with anything
// else served from loopback during development.
const CookieName = "tp_session"

// DefaultTTL is how long a console session lasts. Long enough for a working day,
// short enough that revoking an account matters within one.
const DefaultTTL = 12 * time.Hour

// Issuer identifies our tokens, so a token minted by something else that happens
// to share the key is still rejected.
const Issuer = "trust-proxy"

// Authn signs and verifies session tokens.
type Authn struct {
	secret    []byte
	bootstrap string // one-time code for creating the first admin over the network
	ttl       time.Duration
	now       func() time.Time

	mu      sync.Mutex
	tickets map[string]ticket
}

// Claims is our JWT payload.
type Claims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	Role     string `json:"role"`
	// Epoch is the account's SessionEpoch at issue time. The middleware compares it
	// with the current record, so bumping the epoch ends every session minted before
	// it — which is what makes changing a password a real revocation rather than
	// advice. Role is *not* trusted from here for the same family of reasons: the
	// middleware re-reads it.
	Epoch int `json:"epoch,omitempty"`
}

// New loads (or creates) the signing key at dir/jwt-secret.
//
// Persisted, so sessions survive a restart — a gateway that logs everyone out
// every time it reloads its config would train people to hate it. 0600: with this
// key anyone can mint an admin session.
func New(dir string) (*Authn, error) {
	a := &Authn{ttl: DefaultTTL, now: time.Now}
	path := filepath.Join(dir, "jwt-secret")
	b, err := os.ReadFile(path)
	switch {
	case err == nil && len(b) >= 32:
		a.secret = b
	case err == nil || os.IsNotExist(err):
		// Missing or too short (a truncated write): mint a fresh one.
		a.secret = make([]byte, 32)
		if _, err := rand.Read(a.secret); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, a.secret, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
	default:
		return nil, err
	}
	return a, nil
}

// GatewayID is a stable, non-secret fingerprint of this installation.
//
// It exists so a cached CLI credential can tell "this gateway was reinstalled"
// apart from "your key was revoked". Those produce the same 401 and want opposite
// advice, and guessing wrong is how a credentials file earns its reputation for
// going stale. Derived from the signing key rather than kept in another file:
// a fresh data directory already means a fresh key, which is exactly the event
// that invalidates every credential anyone holds.
//
// Truncated sha256 with a domain separator — 64 bits is plenty to notice a
// different machine, and none of it walks back to the secret.
func (a *Authn) GatewayID() string {
	sum := sha256.Sum256(append([]byte("trust-proxy gateway id\x00"), a.secret...))
	return hex.EncodeToString(sum[:8])
}

// SetTTL overrides the session lifetime.
func (a *Authn) SetTTL(d time.Duration) {
	if d > 0 {
		a.ttl = d
	}
}

// Issue mints a session token for a user.
func (a *Authn) Issue(u apitypes.User) (token string, expires time.Time, err error) {
	now := a.now()
	exp := now.Add(a.ttl)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Username: u.Username,
		Role:     u.Role,
		Epoch:    u.SessionEpoch,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// Verify checks a token's signature, issuer and expiry.
//
// The algorithm is pinned to HS256: accepting whatever the token's header claims
// is the classic JWT vulnerability (alg=none, or an RSA public key used as an
// HMAC secret).
func (a *Authn) Verify(token string) (*Claims, error) {
	var claims Claims
	parsed, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		return a.secret, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(a.now),
	)
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("token has no subject")
	}
	return &claims, nil
}

// SetCookie writes the session cookie.
//
// Secure is deliberately not set: the console is served over plain HTTP on
// loopback, and a Secure cookie would simply never be stored. SameSite=Strict is
// the actual protection here, together with the Origin check on mutations.
func (a *Authn) SetCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearCookie expires the session cookie (logout).
func (a *Authn) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// SessionToken pulls a session token out of a request: the cookie (browser) or a
// bearer header (anything scripted that logged in rather than using an API key).
func SessionToken(r *http.Request) string {
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

// ---- one-time console tickets --------------------------------------------

// TicketTTL is how long a console ticket is good for. Seconds, not minutes: it
// exists to survive one redirect.
const TicketTTL = 60 * time.Second

type ticket struct {
	userID  string
	expires time.Time
}

// MintTicket issues a single-use token that can be exchanged for a session
// cookie by following a URL.
//
// This is how the desktop shell opens the console already logged in. The shell
// holds an API key (the one `install` wrote into its owner's home) but the
// webview must end up with a cookie, and a cookie can only be set by the origin
// that owns it. Handing the *key* to the page instead would put an admin
// credential inside a web view for as long as the page lives; a ticket is worth
// one redirect and then nothing.
func (a *Authn) MintTicket(userID string) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tickets == nil {
		a.tickets = map[string]ticket{}
	}
	// Opportunistic sweep: there is no background goroutine here, and without it
	// a long-running gateway accumulates one dead entry per app launch.
	now := a.now()
	for k, t := range a.tickets {
		if now.After(t.expires) {
			delete(a.tickets, k)
		}
	}
	a.tickets[tok] = ticket{userID: userID, expires: now.Add(TicketTTL)}
	return tok, nil
}

// RedeemTicket consumes a ticket and returns whose session it buys.
//
// Single use, enforced by deleting before checking expiry: a replayed ticket must
// fail even if it is replayed inside the TTL.
func (a *Authn) RedeemTicket(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tickets[tok]
	if !ok {
		return "", false
	}
	delete(a.tickets, tok)
	if a.now().After(t.expires) {
		return "", false
	}
	return t.userID, true
}

// ---- remote bootstrap ----------------------------------------------------

// BootstrapCode returns the one-time code required to create the first admin
// from off-box, generating and persisting it on first call.
//
// Why it exists: an empty registry has to accept *some* unauthenticated call, or
// a fresh gateway could never be claimed. From loopback that is fine — you are
// already on the machine. Over the network it is a race with anyone who can reach
// the port, so the network path additionally demands a code that only someone
// reading the gateway's log or its data directory has.
func (a *Authn) BootstrapCode(dir string) (string, error) {
	// Under the mutex, like every other field here. It was not: BootstrapCode,
	// CheckBootstrapCode and ClearBootstrapCode all touched a.bootstrap unlocked
	// while running on request goroutines, so a claim racing the clear was a data
	// race on a credential — and two concurrent bootstrap POSTs could both read it
	// as still valid.
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bootstrap != "" {
		return a.bootstrap, nil
	}
	path := filepath.Join(dir, "bootstrap-code")
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) >= 8 {
		a.bootstrap = strings.TrimSpace(string(b))
		return a.bootstrap, nil
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	a.bootstrap = base64.RawURLEncoding.EncodeToString(raw)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(a.bootstrap+"\n"), 0o600); err != nil {
		return "", err
	}
	return a.bootstrap, nil
}

// CheckBootstrapCode compares a supplied code in constant time.
func (a *Authn) CheckBootstrapCode(got string) bool {
	a.mu.Lock()
	code := a.bootstrap
	a.mu.Unlock()
	if code == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(code), []byte(strings.TrimSpace(got))) == 1
}

// ClearBootstrapCode removes the code once the first admin exists — a bootstrap
// code that outlives bootstrap is a spare key under the mat.
func (a *Authn) ClearBootstrapCode(dir string) {
	a.mu.Lock()
	a.bootstrap = ""
	a.mu.Unlock()
	_ = os.Remove(filepath.Join(dir, "bootstrap-code"))
}

// ErrRevoked means the token verified but the account behind it is gone or
// disabled — a valid signature is not the same as a valid account, and a JWT
// outlives both.
var ErrRevoked = fmt.Errorf("account revoked or disabled")
