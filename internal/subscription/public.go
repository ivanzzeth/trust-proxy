package subscription

import (
	"net/url"
	"path"
	"strings"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Redaction at the boundary.
//
// The store keeps the real thing — the gateway needs the URL to refresh and the
// outbounds to dial. What leaves the process is this reduced view. Measured before
// this existed: GET /api/subscriptions handed out an airport subscription link and
// every node's uuid/password to anything that could reach the port.

// ListPublic returns every subscription with its credentials stripped.
func (s *Store) ListPublic() []apitypes.SubscriptionPublic {
	s.mu.Lock()
	defer s.mu.Unlock()
	subs := s.listLocked()
	out := make([]apitypes.SubscriptionPublic, 0, len(subs))
	for _, sub := range subs {
		out = append(out, Public(sub))
	}
	return out
}

// Public reduces one subscription to what a client may see.
func Public(s apitypes.Subscription) apitypes.SubscriptionPublic {
	p := apitypes.SubscriptionPublic{
		ID: s.ID, Name: s.Name,
		HasURL:     s.URL != "",
		HasContent: s.Content != "",
		HasVia:     s.Via != "",
		UserAgent:  s.UserAgent,
		NodeCount:  s.NodeCount,
		UpdatedAt:  s.UpdatedAt,
		LastError:  s.LastError,
		Applied:    s.Applied,
	}
	p.Source = MaskSource(s.URL, s.Content != "")
	for _, n := range s.Nodes {
		p.Nodes = append(p.Nodes, apitypes.NodePublic{
			Tag: n.Tag, Protocol: n.Protocol, Server: n.Server, Port: n.Port,
		})
	}
	return p
}

// MaskSource renders where a subscription came from without revealing the secret
// inside it.
//
// The whole URL is sensitive, hostname included: a real airport link looks like
// https://0052a2c573e6d817fd679254378b2063.z7pm-k4ra-9vqd-xc3t-bl6s.sbs/ — the
// token is a *subdomain*, so showing "the host" would leak it. Only the last two
// labels survive. Identification comes from the name the operator gave it, not
// from this string.
func MaskSource(raw string, pasted bool) string {
	if raw == "" {
		if pasted {
			return "pasted"
		}
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" && u.Scheme != "file" {
		return "***"
	}
	if u.Scheme == "file" {
		// A local path can carry a username; keep the basename, which is what the
		// operator recognises (…/profiles/airport.yaml).
		return "file://***/" + path.Base(u.Path)
	}
	host := u.Hostname()
	labels := strings.Split(host, ".")
	tail := host
	if len(labels) > 2 {
		tail = strings.Join(labels[len(labels)-2:], ".")
	}
	return u.Scheme + "://***." + tail + "/***"
}
