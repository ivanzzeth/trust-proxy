// Package apitypes holds the wire types shared by the backend API
// (internal/api), the domain store (internal/subscription) and the SDK
// (pkg/client). It has no dependencies on those packages, avoiding import
// cycles.
package apitypes

import "encoding/json"

// Node is a single proxy node parsed out of a subscription. Outbound is the
// full sing-box outbound object (JSON) used when applying to the data plane;
// the other fields are for display.
type Node struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Server   string          `json:"server"`
	Port     int             `json:"port"`
	Outbound json.RawMessage `json:"outbound,omitempty"`
}

// Subscription is a remote proxy-provider URL and the nodes parsed from it.
type Subscription struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent,omitempty"`
	Via       string `json:"via,omitempty"` // fetch through this proxy (socks5:// or http://)
	Nodes     []Node `json:"nodes,omitempty"`
	NodeCount int    `json:"node_count"`
	UpdatedAt string `json:"updated_at,omitempty"`
	LastError string `json:"last_error,omitempty"`
	Applied   bool   `json:"applied,omitempty"`
}

// AddSubscriptionRequest is the POST /api/subscriptions body.
type AddSubscriptionRequest struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent,omitempty"`
	Via       string `json:"via,omitempty"`
}

// ErrorResponse is the standard error envelope.
type ErrorResponse struct {
	Error string `json:"error"`
}
