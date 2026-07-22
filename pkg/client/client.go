// Package client is the high-level trust-proxy SDK. It wraps the backend's own
// /api (subscriptions, and later whitelist/alerts) and composes the low-level
// Clash primitive client (pkg/clash) so callers get one ergonomic entry point.
package client

import (
	"bytes"
	"encoding/json"
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
	// APIBaseURL is the trust-proxy backend API, e.g. http://127.0.0.1:9096
	APIBaseURL string
	// ClashAddr / ClashSecret point at the standard Clash API (low-level).
	ClashAddr   string
	ClashSecret string
}

// Client is the high-level SDK. Clash exposes the raw standard primitives.
type Client struct {
	base  string
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
		base: strings.TrimRight(base, "/"),
		hc:   &http.Client{Timeout: 35 * time.Second},
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
func (c *Client) ListSubscriptions() ([]apitypes.Subscription, error) {
	var out []apitypes.Subscription
	err := c.do(http.MethodGet, "/api/subscriptions", nil, &out)
	return out, err
}

// AddSubscription registers and refreshes a subscription. userAgent may be
// empty to use the server default; via (socks5:// or http://) routes the fetch
// through a proxy.
func (c *Client) AddSubscription(name, url, userAgent, via string) (apitypes.Subscription, error) {
	var out apitypes.Subscription
	err := c.do(http.MethodPost, "/api/subscriptions", apitypes.AddSubscriptionRequest{Name: name, URL: url, UserAgent: userAgent, Via: via}, &out)
	return out, err
}

// ImportNodes adds a manual subscription from pasted node text (share links,
// base64, Clash YAML or sing-box JSON) — no network fetch.
func (c *Client) ImportNodes(name, content string) (apitypes.Subscription, error) {
	var out apitypes.Subscription
	err := c.do(http.MethodPost, "/api/subscriptions", apitypes.AddSubscriptionRequest{Name: name, Content: content}, &out)
	return out, err
}

// ApplySubscription applies a subscription's nodes to the running gateway.
func (c *Client) ApplySubscription(id string) (apitypes.Subscription, error) {
	var out apitypes.Subscription
	err := c.do(http.MethodPost, "/api/subscriptions/"+id+"/apply", nil, &out)
	return out, err
}

// DeleteSubscription removes a subscription by id.
func (c *Client) DeleteSubscription(id string) error {
	return c.do(http.MethodDelete, "/api/subscriptions/"+id, nil, nil)
}

// RefreshSubscription re-fetches and re-parses a subscription.
func (c *Client) RefreshSubscription(id string) (apitypes.Subscription, error) {
	var out apitypes.Subscription
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
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e apitypes.ErrorResponse
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		_ = json.Unmarshal(raw, &e)
		if e.Error != "" {
			return fmt.Errorf("%s %s: %s", method, path, e.Error)
		}
		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
