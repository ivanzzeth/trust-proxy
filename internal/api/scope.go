package api

import (
	"net/http"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/history"
	"github.com/ivanzzeth/trust-proxy/internal/users"
	"github.com/ivanzzeth/trust-proxy/pkg/clash"
)

// Per-person scoping of the observability surface.
//
// A shared gateway has several people behind one exit. Letting any account read
// the whole connection list would mean every user can watch every other user's
// destinations — the gateway would leak exactly the thing it exists to control.
// So a client sees its own traffic and only its own.
//
// The filter is applied **server-side, from the authenticated identity**. It is
// never a query parameter: a client-supplied filter is a client-controlled filter,
// which is not a filter at all.
//
// Attribution comes from the inbound account (our fork reports it on each
// connection; internal/detect records it on each event). A source IP would not do:
// NAT collapses many people onto one, and one machine can hold several accounts.

// scopeUser returns the account name a caller's view must be limited to, or ""
// when the caller may see everything (admin, the static token, an unclaimed
// gateway).
func (s *Server) scopeUser(r *http.Request) string {
	u := s.caller(r)
	if u == nil || u.Role == users.RoleAdmin {
		return ""
	}
	return u.Username
}

// scopeConnections drops connections that do not belong to name.
//
// Totals are recomputed from what survives, or the numbers in the corner would
// still describe the whole gateway.
func scopeConnections(snap clash.Connections, name string) clash.Connections {
	if name == "" {
		return snap
	}
	out := clash.Connections{}
	for _, c := range snap.Connections {
		if !strings.EqualFold(c.Metadata.User, name) {
			continue
		}
		out.Connections = append(out.Connections, c)
		out.UploadTotal += c.Upload
		out.DownloadTotal += c.Download
	}
	return out
}

// owns reports whether a record attributed to user belongs to name.
func owns(user, name string) bool {
	return name == "" || strings.EqualFold(user, name)
}

// scopeEvents filters the connection-event ring to one account.
func scopeEvents(evs []detect.Event, name string) []detect.Event {
	if name == "" {
		return evs
	}
	out := make([]detect.Event, 0, len(evs))
	for _, e := range evs {
		if owns(e.User, name) {
			out = append(out, e)
		}
	}
	return out
}

// scopeDetections filters findings to one account.
func scopeDetections(ds []detect.Detection, name string) []detect.Detection {
	if name == "" {
		return ds
	}
	out := make([]detect.Detection, 0, len(ds))
	for _, d := range ds {
		if owns(d.User, name) {
			out = append(out, d)
		}
	}
	return out
}

// scopeHistory filters completed-connection records to one account.
func scopeHistory(rs []history.Record, name string) []history.Record {
	if name == "" {
		return rs
	}
	out := make([]history.Record, 0, len(rs))
	for _, r := range rs {
		if owns(r.User, name) {
			out = append(out, r)
		}
	}
	return out
}
