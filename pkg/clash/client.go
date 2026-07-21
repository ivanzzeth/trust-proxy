// Package clash is the low-level SDK primitive: a Go client for the standard
// Clash REST API (the de-facto interface exposed by sing-box / mihomo / clash).
// It is intentionally generic and reusable — higher layers (pkg/client) build
// ergonomic, trust-proxy-specific helpers on top of it.
package clash

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to a Clash external controller (e.g. 127.0.0.1:9090).
type Client struct {
	base   string
	secret string
	hc     *http.Client
}

// New builds a client. addr is host:port; secret may be empty.
func New(addr, secret string) *Client {
	base := addr
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	return &Client{
		base:   strings.TrimRight(base, "/"),
		secret: secret,
		hc:     &http.Client{Timeout: 15 * time.Second},
	}
}

// Version is GET /version.
type Version struct {
	Version string `json:"version"`
	Meta    bool   `json:"meta"`
	Premium bool   `json:"premium"`
}

// Metadata mirrors the Clash connection metadata object.
type Metadata struct {
	Network         string `json:"network"`
	Type            string `json:"type"`
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	SourcePort      string `json:"sourcePort"`
	DestinationPort string `json:"destinationPort"`
	Host            string `json:"host"`
	Process         string `json:"process"`
	ProcessPath     string `json:"processPath"`
}

// Connection is one active connection from GET /connections.
type Connection struct {
	ID       string   `json:"id"`
	Metadata Metadata `json:"metadata"`
	Upload   int64    `json:"upload"`
	Download int64    `json:"download"`
	Start    string   `json:"start"`
	Chains   []string `json:"chains"`
	Rule     string   `json:"rule"`
}

// Connections is the GET /connections snapshot.
type Connections struct {
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Connections   []Connection `json:"connections"`
}

// Version returns the controller version.
func (c *Client) Version() (Version, error) {
	var v Version
	err := c.do(http.MethodGet, "/version", &v)
	return v, err
}

// Connections returns the current connection snapshot.
func (c *Client) Connections() (Connections, error) {
	var conns Connections
	err := c.do(http.MethodGet, "/connections", &conns)
	return conns, err
}

// CloseConnection closes one connection by id (DELETE /connections/{id}).
func (c *Client) CloseConnection(id string) error {
	return c.do(http.MethodDelete, "/connections/"+url.PathEscape(id), nil)
}

// CloseAllConnections closes every connection (DELETE /connections).
func (c *Client) CloseAllConnections() error {
	return c.do(http.MethodDelete, "/connections", nil)
}

func (c *Client) do(method, path string, out any) error {
	req, err := http.NewRequest(method, c.base+path, nil)
	if err != nil {
		return err
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("clash api %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
