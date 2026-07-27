package client

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Auth surface of the SDK.
//
// Two credential shapes, matching the two kinds of caller:
//
//   - an **API key** (Options.Token starting with tp_, or SetAPIKey) — what the
//     CLI and scripts use. Stateless, revocable per key.
//   - a **session** from Login — what a human-driven tool uses when it only has a
//     password. The cookie is kept in a jar on this client, so a CLI can log in
//     once and keep going.

// AuthState asks what a caller may do without any credential: bootstrap the first
// admin, log in, or register.
func (c *Client) AuthState() (apitypes.AuthState, error) {
	var out apitypes.AuthState
	err := c.do(http.MethodGet, "/api/auth/state", nil, &out)
	return out, err
}

// Me returns the account behind the current credential.
func (c *Client) Me() (apitypes.User, error) {
	var out apitypes.User
	err := c.do(http.MethodGet, "/api/auth/me", nil, &out)
	return out, err
}

// Bootstrap creates the first admin. code is required only when the gateway is
// reached off-loopback (it is printed in the gateway's log at startup).
func (c *Client) Bootstrap(username, password, code string) (apitypes.Session, error) {
	return c.bootstrap(username, password, code, false)
}

// BootstrapWithGeneratedPassword is Bootstrap for a caller that made the password
// up and told nobody — `install`, claiming a gateway on behalf of the person who
// ran it. The account is marked so that setting a real password afterwards is a
// *set* and not a *change*: requiring a current password there would make the
// documented next step (`trust-proxy user passwd <name>`) impossible, since the
// current one is 32 random bytes that were never printed.
func (c *Client) BootstrapWithGeneratedPassword(username, password, code string) (apitypes.Session, error) {
	return c.bootstrap(username, password, code, true)
}

func (c *Client) bootstrap(username, password, code string, generated bool) (apitypes.Session, error) {
	// Keep the session the server issues, exactly as Login does. Bootstrap did not,
	// and the very next call — minting the new admin's first API key — went out
	// unauthenticated against a registry that had just stopped being empty, so it
	// 401'd. Claiming a gateway and then being unable to use it is not a state
	// worth having.
	c.ensureJar()
	var out apitypes.Session
	body := map[string]any{"username": username, "password": password}
	if code != "" {
		body["code"] = code
	}
	if generated {
		body["generated_password"] = true
	}
	err := c.do(http.MethodPost, "/api/auth/bootstrap", body, &out)
	return out, err
}

// Login exchanges a password for a session, which this client then carries.
func (c *Client) Login(username, password string) (apitypes.Session, error) {
	c.ensureJar()
	var out apitypes.Session
	err := c.do(http.MethodPost, "/api/auth/login", apitypes.LoginRequest{Username: username, Password: password}, &out)
	return out, err
}

// ConsoleTicket mints a single-use token that turns into a browser session by
// following its URL.
//
// For a caller that holds an API key but needs a *cookie*: the desktop shell
// opening the console in its webview. Short-lived and one-shot, so the key itself
// never enters the page.
func (c *Client) ConsoleTicket() (apitypes.ConsoleTicket, error) {
	var out apitypes.ConsoleTicket
	err := c.do(http.MethodPost, "/api/auth/ticket", nil, &out)
	return out, err
}

// Logout drops the session server-side and locally.
func (c *Client) Logout() error {
	err := c.do(http.MethodPost, "/api/auth/logout", nil, nil)
	c.hc.Jar = nil
	return err
}

// Register self-signs-up, if an admin has opened registration. Always a plain
// user, never an admin.
func (c *Client) Register(username, password string) (apitypes.Session, error) {
	c.ensureJar()
	var out apitypes.Session
	err := c.do(http.MethodPost, "/api/auth/register", apitypes.LoginRequest{Username: username, Password: password}, &out)
	return out, err
}

// AuthSettings reads the registry-wide auth knobs (admin).
func (c *Client) AuthSettings() (apitypes.AuthSettings, error) {
	var out apitypes.AuthSettings
	err := c.do(http.MethodGet, "/api/auth/settings", nil, &out)
	return out, err
}

// SetAuthSettings opens or closes self-registration (admin).
func (c *Client) SetAuthSettings(s apitypes.AuthSettings) (apitypes.AuthSettings, error) {
	var out apitypes.AuthSettings
	err := c.do(http.MethodPut, "/api/auth/settings", s, &out)
	return out, err
}

// SetAPIKey swaps the credential this client presents.
func (c *Client) SetAPIKey(key string) { c.token = key }

// ---- user administration (admin) ----------------------------------------

// Users lists the accounts.
func (c *Client) Users() ([]apitypes.User, error) {
	var out []apitypes.User
	err := c.do(http.MethodGet, "/api/users", nil, &out)
	return out, err
}

// CreateUser adds an account. role is admin|user; the first account ever created
// is promoted to admin regardless.
func (c *Client) CreateUser(username, password, role string) (apitypes.User, error) {
	var out apitypes.User
	err := c.do(http.MethodPost, "/api/users",
		map[string]string{"username": username, "password": password, "role": role}, &out)
	return out, err
}

// PatchUser applies any subset of role / disabled / password / proxy_password.
// A nil field is left alone; an empty proxy password removes proxy access.
func (c *Client) PatchUser(id string, req apitypes.PatchUserRequest) (apitypes.User, error) {
	var out apitypes.User
	err := c.do(http.MethodPatch, "/api/users/"+url.PathEscape(id), req, &out)
	return out, err
}

// DeleteUser removes an account (never the last admin).
func (c *Client) DeleteUser(id string) error {
	return c.do(http.MethodDelete, "/api/users/"+url.PathEscape(id), nil, nil)
}

// CreateAPIKey mints a key for an account. The raw key is in the response and
// nowhere else — the server keeps only its hash.
func (c *Client) CreateAPIKey(userID, label string, expiresInDays int) (apitypes.APIKeyCreated, error) {
	var out apitypes.APIKeyCreated
	body := map[string]any{"label": label}
	if expiresInDays > 0 {
		body["expires_in_days"] = expiresInDays
	}
	err := c.do(http.MethodPost, "/api/users/"+url.PathEscape(userID)+"/apikeys", body, &out)
	return out, err
}

// DeleteAPIKey revokes one key.
func (c *Client) DeleteAPIKey(userID, keyID string) error {
	return c.do(http.MethodDelete, "/api/users/"+url.PathEscape(userID)+"/apikeys/"+url.PathEscape(keyID), nil, nil)
}

// ---- permit requests -----------------------------------------------------

// RequestPermit asks the gateway's admins to permit a destination. It creates a
// disabled rule; nothing changes until somebody approves it.
func (c *Client) RequestPermit(host, reason string) (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodPost, "/api/permit-requests",
		map[string]string{"host": host, "reason": reason}, &out)
	return out, err
}

// PermitRequests lists pending requests: all of them for an admin, your own for a
// client.
func (c *Client) PermitRequests() ([]apitypes.CustomRule, error) {
	var out []apitypes.CustomRule
	err := c.do(http.MethodGet, "/api/permit-requests", nil, &out)
	return out, err
}

// ApprovePermitRequest turns a request into policy (admin).
func (c *Client) ApprovePermitRequest(id string) ([]apitypes.CustomRule, error) {
	var out []apitypes.CustomRule
	err := c.do(http.MethodPost, "/api/permit-requests/"+url.PathEscape(id)+"/approve", nil, &out)
	return out, err
}

// DenyPermitRequest discards a request (admin).
func (c *Client) DenyPermitRequest(id string) ([]apitypes.CustomRule, error) {
	var out []apitypes.CustomRule
	err := c.do(http.MethodDelete, "/api/permit-requests/"+url.PathEscape(id), nil, &out)
	return out, err
}

// ensureJar gives this client a cookie jar so a session survives across calls.
func (c *Client) ensureJar() {
	if c.hc.Jar != nil {
		return
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return
	}
	c.hc.Jar = jar
	if c.hc.Timeout == 0 {
		c.hc.Timeout = 35 * time.Second
	}
}
