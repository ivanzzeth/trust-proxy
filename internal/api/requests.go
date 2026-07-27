package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/users"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Permit requests.
//
// A client's traffic is blocked by the *gateway's* policy, and a client cannot
// widen that policy — only make its own side stricter. Without a way to ask, the
// only recourse is a message on some other channel, so people give up and the
// gateway gets loosened wholesale "to stop the complaints".
//
// A request needs no store of its own: it is a rule that is not in force yet. It
// travels as a **disabled** custom rule tagged pack="request:<username>" with the
// reason in Note, and approval is the admin enabling it. That also means requests
// show up in the same place as the policy they would change, rather than in a
// separate inbox nobody opens.

// handleCreatePermitRequest lets a client ask for a destination to be permitted.
//
// Deliberately narrow: the caller chooses a host and a reason, and nothing else.
// It cannot pick the egress, cannot pre-set Permit, and the rule lands disabled —
// so a client can never widen policy by calling this, only queue a proposal.
func (s *Server) handleCreatePermitRequest(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	caller := s.caller(r)
	if caller == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		Host   string `json:"host"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	host := strings.TrimSpace(strings.ToLower(req.Host))
	if host == "" {
		writeErr(w, http.StatusBadRequest, "host is required")
		return
	}
	if len(req.Reason) > 500 {
		writeErr(w, http.StatusBadRequest, "reason is too long")
		return
	}
	match := apitypes.CustomMatchDomainSuffix
	if strings.Contains(host, "/") || isIPish(host) {
		match = apitypes.CustomMatchIPCIDR
	}
	// Permit is set, Enabled is not: a disabled rule has no effect at all, so the
	// request grants nothing until an admin flips it on. (A rule that neither
	// permits nor routes is a no-op and the store rightly refuses it, so "pending"
	// has to be expressed by the enabled flag rather than by an empty rule.)
	permit := true
	rule := apitypes.CustomRule{
		Match: match, Value: host,
		Action: apitypes.CustomEgressNone, Egress: apitypes.CustomEgressNone,
		Permit:  &permit,
		Pack:    apitypes.PackRequestPrefix + caller.Username,
		Note:    strings.TrimSpace(req.Reason),
		Enabled: false,
	}
	if _, err := s.cr.Add(rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// No rebuild: a disabled rule changes nothing in the data plane, and rebuilding
	// for it would make an unprivileged call able to bounce the box.
	writeJSON(w, http.StatusOK, map[string]any{
		"requested": host,
		"pack":      rule.Pack,
		"pending":   true,
	})
}

// handleListPermitRequests returns pending requests: all of them for an admin,
// only their own for a client.
func (s *Server) handleListPermitRequests(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeArray(w, http.StatusOK, []apitypes.CustomRule{})
		return
	}
	caller := s.caller(r)
	mine := ""
	if caller != nil && caller.Role != users.RoleAdmin {
		mine = apitypes.PackRequestPrefix + caller.Username
	}
	out := []apitypes.CustomRule{}
	for _, rule := range s.cr.Get().Rules {
		if !strings.HasPrefix(rule.Pack, apitypes.PackRequestPrefix) {
			continue
		}
		if mine != "" && !strings.EqualFold(rule.Pack, mine) {
			continue
		}
		out = append(out, rule)
	}
	writeArray(w, http.StatusOK, out)
}

// handleApprovePermitRequest turns a pending request into policy: Permit granted
// and the rule enabled, in one step, so approving is not a three-field edit an
// admin can get wrong.
func (s *Server) handleApprovePermitRequest(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	id := r.PathValue("id")
	var found *apitypes.CustomRule
	for _, rule := range s.cr.Get().Rules {
		if rule.ID == id {
			r := rule
			found = &r
			break
		}
	}
	if found == nil {
		writeErr(w, http.StatusNotFound, "no such request")
		return
	}
	if !strings.HasPrefix(found.Pack, apitypes.PackRequestPrefix) {
		writeErr(w, http.StatusBadRequest, "that rule is not a pending request")
		return
	}
	enabled := true
	rules, err := s.cr.Update(id, apitypes.PatchCustomRuleRequest{Enabled: &enabled})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.crApplier != nil {
		if err := s.crApplier.SetCustomRules(rules); err != nil {
			writeErr(w, http.StatusBadGateway, "apply rules: "+err.Error())
			return
		}
	}
	writeArray(w, http.StatusOK, rules.Rules)
}

// handleDenyPermitRequest removes a pending request.
func (s *Server) handleDenyPermitRequest(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	id := r.PathValue("id")
	// The same check its sibling approve does, and for the same reason: this endpoint
	// takes an id and this store holds every custom rule, so without it "deny a
	// request" deleted whatever rule that id named — an ordinary, enabled piece of
	// policy included.
	var found *apitypes.CustomRule
	for _, rule := range s.cr.Get().Rules {
		if rule.ID == id {
			r := rule
			found = &r
			break
		}
	}
	if found == nil {
		writeErr(w, http.StatusNotFound, "no such request")
		return
	}
	if !strings.HasPrefix(found.Pack, apitypes.PackRequestPrefix) {
		writeErr(w, http.StatusBadRequest, "that rule is not a pending request")
		return
	}
	rules, err := s.cr.Remove(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	// And re-apply. Without this the store and the data plane diverged: whatever was
	// removed stayed in force until something else happened to rebuild, so "revoked"
	// read as done and was not. A pending request is disabled and grants nothing, so
	// this is usually a no-op — usually is not a reason to skip it, and an approved
	// request that is later denied is the case where it is not.
	if s.crApplier != nil {
		if err := s.crApplier.SetCustomRules(rules); err != nil {
			writeErr(w, http.StatusBadGateway, "apply rules: "+err.Error())
			return
		}
	}
	writeArray(w, http.StatusOK, rules.Rules)
}

// isIPish is a cheap "does this look like an address or CIDR" test, enough to pick
// the matcher; the store validates properly.
func isIPish(s string) bool {
	digits, dots := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.':
			dots++
		case r == ':' || r == '/':
			return true
		default:
			return false
		}
	}
	return dots == 3 && digits >= 4
}
