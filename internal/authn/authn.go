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
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
}

// Claims is our JWT payload.
type Claims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	Role     string `json:"role"`
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
	if a.bootstrap == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a.bootstrap), []byte(strings.TrimSpace(got))) == 1
}

// ClearBootstrapCode removes the code once the first admin exists — a bootstrap
// code that outlives bootstrap is a spare key under the mat.
func (a *Authn) ClearBootstrapCode(dir string) {
	a.bootstrap = ""
	_ = os.Remove(filepath.Join(dir, "bootstrap-code"))
}

// ErrRevoked means the token verified but the account behind it is gone or
// disabled — a valid signature is not the same as a valid account, and a JWT
// outlives both.
var ErrRevoked = fmt.Errorf("account revoked or disabled")
