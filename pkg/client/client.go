// Package client is the high-level trust-proxy SDK. It wraps the backend's own
// /api (subscriptions, and later whitelist/alerts) and composes the low-level
// Clash primitive client (pkg/clash) so callers get one ergonomic entry point.
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
	"github.com/ivanzzeth/trust-proxy/pkg/clash"
)

// Options configures the SDK's two endpoints.
type Options struct {
	// APIBaseURL is the trust-proxy backend API, e.g. http://127.0.0.1:21585
	APIBaseURL string
	// ClashAddr / ClashSecret point at the standard Clash API (low-level).
	ClashAddr   string
	ClashSecret string
	// Token is the bearer token required when the backend runs with --api-token
	// (probe mode). Empty for a loopback backend.
	Token string
}

// Client is the high-level SDK. Clash exposes the raw standard primitives.
type Client struct {
	base  string
	token string
	hc    *http.Client
	Clash *clash.Client
}

// New builds the SDK client.
func New(o Options) *Client {
	base := o.APIBaseURL
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	c := &Client{
		base:  strings.TrimRight(base, "/"),
		token: o.Token,
		hc:    &http.Client{Timeout: 35 * time.Second},
	}
	if o.ClashAddr != "" {
		c.Clash = clash.New(o.ClashAddr, o.ClashSecret)
	}
	return c
}

// ---- high-level: our backend /api ----------------------------------------

// Health checks the backend is up.
func (c *Client) Health() error {
	return c.do(http.MethodGet, "/api/health", nil, nil)
}

// ListSubscriptions returns all subscriptions.
func (c *Client) ListSubscriptions() ([]apitypes.SubscriptionPublic, error) {
	var out []apitypes.SubscriptionPublic
	err := c.do(http.MethodGet, "/api/subscriptions", nil, &out)
	return out, err
}

// AddSubscription registers and refreshes a subscription. userAgent may be
// empty to use the server default; via (socks5:// or http://) routes the fetch
// through a proxy.
func (c *Client) AddSubscription(name, url, userAgent, via string) (apitypes.SubscriptionPublic, error) {
	var out apitypes.SubscriptionPublic
	err := c.do(http.MethodPost, "/api/subscriptions", apitypes.AddSubscriptionRequest{Name: name, URL: url, UserAgent: userAgent, Via: via}, &out)
	return out, err
}

// ImportNodes adds a manual subscription from pasted node text (share links,
// base64, Clash YAML or sing-box JSON) — no network fetch.
func (c *Client) ImportNodes(name, content string) (apitypes.SubscriptionPublic, error) {
	var out apitypes.SubscriptionPublic
	err := c.do(http.MethodPost, "/api/subscriptions", apitypes.AddSubscriptionRequest{Name: name, Content: content}, &out)
	return out, err
}

// ApplySubscription applies a subscription's nodes to the running gateway.
func (c *Client) ApplySubscription(id string) (apitypes.SubscriptionPublic, error) {
	var out apitypes.SubscriptionPublic
	err := c.do(http.MethodPost, "/api/subscriptions/"+id+"/apply", nil, &out)
	return out, err
}

// DeleteSubscription removes a subscription by id.
func (c *Client) DeleteSubscription(id string) error {
	return c.do(http.MethodDelete, "/api/subscriptions/"+id, nil, nil)
}

// RefreshSubscription re-fetches and re-parses a subscription.
func (c *Client) RefreshSubscription(id string) (apitypes.SubscriptionPublic, error) {
	var out apitypes.SubscriptionPublic
	err := c.do(http.MethodPost, "/api/subscriptions/"+id+"/refresh", nil, &out)
	return out, err
}

// ---- ergonomic delegations to the low-level Clash primitives --------------

// Connections returns the current Clash connection snapshot.
func (c *Client) Connections() (clash.Connections, error) {
	if c.Clash == nil {
		return clash.Connections{}, fmt.Errorf("clash client not configured")
	}
	return c.Clash.Connections()
}

// Kill closes one connection by id via the Clash API.
func (c *Client) Kill(id string) error {
	if c.Clash == nil {
		return fmt.Errorf("clash client not configured")
	}
	return c.Clash.CloseConnection(id)
}

// APIError is a non-2xx response, carrying the status so callers can react to
// *which* failure it was.
//
// Specifically so nobody has to grep the message for "unauthorized" again: the
// CLI decorates a 401 with how to authenticate, and a substring match on prose
// both misses rewordings and fires on unrelated errors that happen to contain the
// word. The rendered text is unchanged, so existing output is the same.
type APIError struct {
	Method  string
	Path    string
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s: %s", e.Method, e.Path, e.Message)
}

// Unauthorized reports a 401 — no credential, or one the gateway refused.
func (e *APIError) Unauthorized() bool { return e.Status == http.StatusUnauthorized }

// IsUnauthorized reports whether err is a 401 from the API, at any wrap depth.
func IsUnauthorized(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Unauthorized()
}

func (c *Client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e apitypes.ErrorResponse
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		_ = json.Unmarshal(raw, &e)
		msg := e.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
