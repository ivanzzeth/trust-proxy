package authn

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func newAuthn(t *testing.T) (*Authn, string) {
	t.Helper()
	dir := t.TempDir()
	a, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return a, dir
}

var alice = apitypes.User{ID: "u1", Username: "alice", Role: "admin"}

func TestIssueAndVerify(t *testing.T) {
	a, _ := newAuthn(t)
	token, exp, err := a.Issue(alice)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.After(time.Now()) {
		t.Fatal("expiry is in the past")
	}
	claims, err := a.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "u1" || claims.Username != "alice" || claims.Role != "admin" {
		t.Fatalf("claims = %+v", claims)
	}
}

// The signing key persists, or every config reload would log everybody out.
func TestSecretPersistsAndIsPrivate(t *testing.T) {
	a, dir := newAuthn(t)
	token, _, _ := a.Issue(alice)

	again, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Verify(token); err != nil {
		t.Fatalf("a session did not survive a restart: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "jwt-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("jwt-secret mode = %o, want 600 (this key mints admin sessions)", perm)
	}
	// A different gateway's key must not validate our token.
	other, _ := newAuthn(t)
	if _, err := other.Verify(token); err == nil {
		t.Fatal("a token signed with another key was accepted")
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	a, _ := newAuthn(t)
	a.SetTTL(time.Minute)
	token, _, _ := a.Issue(alice)
	a.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := a.Verify(token); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

func TestTamperedTokenIsRejected(t *testing.T) {
	a, _ := newAuthn(t)
	token, _, _ := a.Issue(alice)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape %q", token)
	}
	// Flip a byte of the signature.
	sig := []byte(parts[2])
	sig[0] ^= 'A' ^ 'B'
	if _, err := a.Verify(parts[0] + "." + parts[1] + "." + string(sig)); err == nil {
		t.Fatal("a token with a broken signature was accepted")
	}
	if _, err := a.Verify("garbage"); err == nil {
		t.Fatal("garbage was accepted as a token")
	}
}

// alg=none is the classic JWT hole: a verifier that trusts the token's own header
// can be handed an unsigned token claiming to be an admin.
func TestUnsignedTokenIsRejected(t *testing.T) {
	a, _ := newAuthn(t)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "u1", Issuer: Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Username: "attacker", Role: "admin",
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Verify(unsigned); err == nil {
		t.Fatal("an alg=none token was accepted")
	}
}

func TestWrongIssuerIsRejected(t *testing.T) {
	a, _ := newAuthn(t)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "u1", Issuer: "somebody-else",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Role: "admin",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Verify(token); err == nil {
		t.Fatal("a token from another issuer was accepted")
	}
}

// The cookie must be invisible to page scripts: an XSS in the console could read
// localStorage, but not this.
func TestCookieIsHttpOnlyAndStrict(t *testing.T) {
	a, _ := newAuthn(t)
	rec := httptest.NewRecorder()
	a.SetCookie(rec, "tok", time.Now().Add(time.Hour))
	res := rec.Result()
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies", len(cookies))
	}
	c := cookies[0]
	if c.Name != CookieName || c.Value != "tok" {
		t.Fatalf("cookie = %+v", c)
	}
	if !c.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("session cookie must be SameSite=Strict")
	}
	if c.Path != "/" {
		t.Errorf("cookie path = %q", c.Path)
	}

	rec = httptest.NewRecorder()
	a.ClearCookie(rec)
	if got := rec.Result().Cookies()[0].MaxAge; got != -1 {
		t.Errorf("logout cookie MaxAge = %d, want -1", got)
	}
}

func TestSessionTokenFromCookieOrBearer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	if got := SessionToken(r); got != "" {
		t.Fatalf("expected no token, got %q", got)
	}
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "from-cookie"})
	if got := SessionToken(r); got != "from-cookie" {
		t.Fatalf("token = %q", got)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	r2.Header.Set("Authorization", "Bearer from-header")
	if got := SessionToken(r2); got != "from-header" {
		t.Fatalf("token = %q", got)
	}
}

// The bootstrap code is what stops a stranger claiming the first admin account on
// a gateway exposed to a network before its owner finishes setup.
func TestBootstrapCode(t *testing.T) {
	a, dir := newAuthn(t)
	code, err := a.BootstrapCode(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) < 16 {
		t.Fatalf("bootstrap code %q is too short to be worth having", code)
	}
	if !a.CheckBootstrapCode(code) {
		t.Fatal("the code we just generated was rejected")
	}
	if !a.CheckBootstrapCode(" " + code + "\n") {
		t.Fatal("surrounding whitespace should be tolerated (people paste)")
	}
	if a.CheckBootstrapCode("wrong") || a.CheckBootstrapCode("") {
		t.Fatal("a wrong code was accepted")
	}
	// Stable across calls and persisted (the operator reads it from the log or the
	// file, possibly after a restart).
	again, _ := a.BootstrapCode(dir)
	if again != code {
		t.Fatal("the code changed between calls")
	}
	info, err := os.Stat(filepath.Join(dir, "bootstrap-code"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("bootstrap-code mode = %o, want 600", perm)
	}
	// Once bootstrap is done the code must be gone, not lying around.
	a.ClearBootstrapCode(dir)
	if a.CheckBootstrapCode(code) {
		t.Fatal("a cleared code still validates")
	}
	if _, err := os.Stat(filepath.Join(dir, "bootstrap-code")); !os.IsNotExist(err) {
		t.Fatal("the bootstrap code file outlived bootstrap")
	}
}
