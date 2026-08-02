package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/nodes"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleListCustomRules(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	writeArray(w, http.StatusOK, s.cr.Get().Rules)
}

func (s *Server) handleAddCustomRule(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	prev := s.cr.Get()
	var req apitypes.CustomRule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.ID = "" // ID is derived by the store
	// In client mode this machine does not enforce egress policy — the gateway it
	// exits through does — so a local rule that grants Permit cannot have any
	// effect: that traffic still meets the gateway's default-deny. Refusing it is
	// the honest answer; accepting it would leave someone staring at a rule they
	// think opened something.
	if err := s.refuseIneffectivePermit(req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rules, err := s.cr.Add(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error()) // validation error
		return
	}
	if err := s.applyCustomRules(rules); err != nil {
		_, _ = s.cr.Set(prev) // roll back so the store matches the running plane
		writeErr(w, http.StatusBadGateway, "apply custom rule: "+err.Error())
		return
	}
	writeArray(w, http.StatusCreated, rules.Rules)
}

func (s *Server) handlePatchCustomRule(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	prev := s.cr.Get()
	var req apitypes.PatchCustomRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	rules, err := s.cr.Update(r.PathValue("id"), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.applyCustomRules(rules); err != nil {
		_, _ = s.cr.Set(prev)
		writeErr(w, http.StatusBadGateway, "apply custom rule: "+err.Error())
		return
	}
	writeArray(w, http.StatusOK, rules.Rules)
}

func (s *Server) handleDeleteCustomRule(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	prev := s.cr.Get()
	rules, err := s.cr.Remove(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyCustomRules(rules); err != nil {
		_, _ = s.cr.Set(prev)
		writeErr(w, http.StatusBadGateway, "apply custom rule: "+err.Error())
		return
	}
	writeArray(w, http.StatusOK, rules.Rules)
}

func (s *Server) handleMoveCustomRule(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	prev := s.cr.Get()
	var req struct {
		// Dir <0 up / >0 down by one step. Ignored when To is set.
		Dir int `json:"dir"`
		// To "top" promotes the rule to index 0 (highest priority). Not a pin.
		To string `json:"to,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	var (
		rules customrules.Rules
		err   error
	)
	switch strings.ToLower(strings.TrimSpace(req.To)) {
	case "top":
		rules, err = s.cr.MoveTop(r.PathValue("id"))
	case "":
		if req.Dir == 0 {
			writeErr(w, http.StatusBadRequest, "dir must be non-zero, or to=top")
			return
		}
		rules, err = s.cr.Move(r.PathValue("id"), req.Dir)
	default:
		writeErr(w, http.StatusBadRequest, "to must be \"top\" when set")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyCustomRules(rules); err != nil {
		_, _ = s.cr.Set(prev)
		writeErr(w, http.StatusBadGateway, "apply custom rule: "+err.Error())
		return
	}
	writeArray(w, http.StatusOK, rules.Rules)
}

// ---- Allow packs (named groups of custom rules + optional rule sets) -----

func (s *Server) handlePackCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, customrules.Presets)
}

func (s *Server) handleApplyPack(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	var req struct {
		Catalog string                `json:"catalog,omitempty"`
		Name    string                `json:"name,omitempty"`
		Rules   []apitypes.CustomRule `json:"rules,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	name := req.Name
	rules := req.Rules
	var packRS []apitypes.PackRuleSet
	if req.Catalog != "" {
		var found *apitypes.PackPreset
		for i := range customrules.Presets {
			if customrules.Presets[i].Name == req.Catalog {
				found = &customrules.Presets[i]
				break
			}
		}
		if found == nil {
			writeErr(w, http.StatusBadRequest, "unknown preset: "+req.Catalog)
			return
		}
		name = found.Name
		rules = found.Rules
		packRS = found.RuleSets
	}
	if name == "" || (len(rules) == 0 && len(packRS) == 0) {
		writeErr(w, http.StatusBadRequest, "a catalog name or a non-empty {name, rules|rule_sets} is required")
		return
	}

	prevCR := s.cr.Get()
	var prevRS ruleset.Sets
	if s.rs != nil {
		prevRS = s.rs.Get()
	}

	// 1) Upsert catalog rule sets (community coverage). Add is tag-idempotent.
	if len(packRS) > 0 {
		if s.rs == nil {
			writeErr(w, http.StatusServiceUnavailable, "rule sets not available")
			return
		}
		for _, prs := range packRS {
			entry, ok := ruleset.CatalogByTag(prs.CatalogTag)
			if !ok {
				writeErr(w, http.StatusBadRequest, "unknown rule-set catalog tag: "+prs.CatalogTag)
				return
			}
			role := prs.Role
			if role == "" {
				role = entry.SuggestedRole
			}
			role = apitypes.NormalizeRuleRole(role)
			if !validRole(role) {
				writeErr(w, http.StatusBadRequest, "invalid role for "+prs.CatalogTag+": "+role)
				return
			}
			// Merge axes when another pack already imported the same tag
			// (e.g. China-wide permit + China-direct route → permit+route-direct).
			for _, existing := range s.rs.Get().Sets {
				if existing.Tag == entry.Tag {
					role = apitypes.MergeRuleRoles(existing.Role, role)
					break
				}
			}
			rs := apitypes.RuleSet{
				Tag: entry.Tag, Name: entry.Name, Type: "remote", Format: entry.Format,
				URL: ruleset.PreferredURL(entry), DownloadDetour: "direct", UpdateInterval: "1d",
				Role: role, Enabled: true,
			}
			if _, err := s.rs.Add(rs); err != nil {
				_ = s.rollbackRuleSets(prevRS)
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
	}

	// 2) Replace pack custom rules (overwrite stale matchers from older versions).
	out, err := s.cr.ReplacePack(name, rules)
	if err != nil {
		_ = s.rollbackRuleSets(prevRS)
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// 3) Single plane rebuild: rulesets first (manager state), then custom rules.
	if len(packRS) > 0 {
		if err := s.applyRuleSets(s.rs.Get()); err != nil {
			_, _ = s.cr.Set(prevCR)
			_ = s.rollbackRuleSets(prevRS)
			writeErr(w, http.StatusBadGateway, "apply pack rule sets: "+err.Error())
			return
		}
	}
	if err := s.applyCustomRules(out); err != nil {
		_, _ = s.cr.Set(prevCR)
		_ = s.rollbackRuleSets(prevRS)
		_ = s.applyRuleSets(prevRS)
		writeErr(w, http.StatusBadGateway, "apply pack: "+err.Error())
		return
	}

	// Applying a pack changes two things, so this one is a genuine result object
	// (not a list endpoint): its rules plus the rule sets it imported.
	writeJSON(w, http.StatusCreated, apitypes.PackApplyResult{
		Rules:    nonNil(out.Rules),
		RuleSets: nonNil(packRS),
	})
}

// rollbackRuleSets restores the rule-set store to a previous snapshot (best-effort).
func (s *Server) rollbackRuleSets(prev ruleset.Sets) error {
	if s.rs == nil {
		return nil
	}
	// Replace by removing extras then re-adding prev — simplest: Set via Remove+Add.
	cur := s.rs.Get()
	for _, rs := range cur.Sets {
		still := false
		for _, p := range prev.Sets {
			if p.Tag == rs.Tag {
				still = true
				break
			}
		}
		if !still {
			_, _ = s.rs.Remove(rs.Tag)
		}
	}
	for _, p := range prev.Sets {
		_, _ = s.rs.Add(p)
	}
	return nil
}

func (s *Server) handlePatchPack(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	name := r.PathValue("name")
	prevCR := s.cr.Get()
	var prevRS ruleset.Sets
	if s.rs != nil {
		prevRS = s.rs.Get()
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	rules, err := s.cr.SetPackEnabled(name, req.Enabled)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if preset := findPackPreset(name); preset != nil && len(preset.RuleSets) > 0 {
		if s.rs == nil {
			writeErr(w, http.StatusServiceUnavailable, "rule sets not available")
			return
		}
		for _, prs := range preset.RuleSets {
			role := prs.Role
			if role == "" {
				if entry, ok := ruleset.CatalogByTag(prs.CatalogTag); ok {
					role = entry.SuggestedRole
				}
			}
			role = apitypes.NormalizeRuleRole(role)
			cur := s.rs.Get()
			var existing *apitypes.RuleSet
			for i := range cur.Sets {
				if cur.Sets[i].Tag == prs.CatalogTag {
					existing = &cur.Sets[i]
					break
				}
			}
			if req.Enabled {
				entry, ok := ruleset.CatalogByTag(prs.CatalogTag)
				if !ok {
					continue
				}
				merged := role
				if existing != nil {
					merged = apitypes.MergeRuleRoles(existing.Role, role)
				}
				rs := apitypes.RuleSet{
					Tag: entry.Tag, Name: entry.Name, Type: "remote", Format: entry.Format,
					URL: ruleset.PreferredURL(entry), DownloadDetour: "direct", UpdateInterval: "1d",
					Role: merged, Enabled: true,
				}
				if existing != nil {
					rs.URL = existing.URL
					rs.Path = existing.Path
					rs.Type = existing.Type
					rs.Format = existing.Format
				}
				if _, err := s.rs.Add(rs); err != nil {
					_, _ = s.cr.Set(prevCR)
					_ = s.rollbackRuleSets(prevRS)
					writeErr(w, http.StatusInternalServerError, err.Error())
					return
				}
			} else if existing != nil {
				left := apitypes.SubtractRuleRoles(existing.Role, role)
				if left == "" {
					if _, err := s.rs.SetEnabled(prs.CatalogTag, false); err != nil {
						_, _ = s.cr.Set(prevCR)
						_ = s.rollbackRuleSets(prevRS)
						writeErr(w, http.StatusInternalServerError, err.Error())
						return
					}
				} else {
					existing.Role = left
					existing.Enabled = true
					if _, err := s.rs.Add(*existing); err != nil {
						_, _ = s.cr.Set(prevCR)
						_ = s.rollbackRuleSets(prevRS)
						writeErr(w, http.StatusInternalServerError, err.Error())
						return
					}
				}
			}
		}
		if err := s.applyRuleSets(s.rs.Get()); err != nil {
			_, _ = s.cr.Set(prevCR)
			_ = s.rollbackRuleSets(prevRS)
			_ = s.applyRuleSets(prevRS)
			writeErr(w, http.StatusBadGateway, "apply pack rule sets: "+err.Error())
			return
		}
	}
	if err := s.applyCustomRules(rules); err != nil {
		_, _ = s.cr.Set(prevCR)
		_ = s.rollbackRuleSets(prevRS)
		_ = s.applyRuleSets(prevRS)
		writeErr(w, http.StatusBadGateway, "apply pack: "+err.Error())
		return
	}
	writeArray(w, http.StatusOK, rules.Rules)
}

func (s *Server) handleDeletePack(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	name := r.PathValue("name")
	prevCR := s.cr.Get()
	var prevRS ruleset.Sets
	if s.rs != nil {
		prevRS = s.rs.Get()
	}
	rules, err := s.cr.RemovePack(name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if preset := findPackPreset(name); preset != nil && len(preset.RuleSets) > 0 {
		if s.rs == nil {
			writeErr(w, http.StatusServiceUnavailable, "rule sets not available")
			return
		}
		for _, prs := range preset.RuleSets {
			role := prs.Role
			if role == "" {
				if entry, ok := ruleset.CatalogByTag(prs.CatalogTag); ok {
					role = entry.SuggestedRole
				}
			}
			role = apitypes.NormalizeRuleRole(role)
			cur := s.rs.Get()
			var existing *apitypes.RuleSet
			for i := range cur.Sets {
				if cur.Sets[i].Tag == prs.CatalogTag {
					existing = &cur.Sets[i]
					break
				}
			}
			if existing == nil {
				continue
			}
			left := apitypes.SubtractRuleRoles(existing.Role, role)
			if left == "" {
				if _, err := s.rs.Remove(prs.CatalogTag); err != nil {
					_, _ = s.cr.Set(prevCR)
					_ = s.rollbackRuleSets(prevRS)
					writeErr(w, http.StatusInternalServerError, err.Error())
					return
				}
			} else {
				existing.Role = left
				existing.Enabled = true
				if _, err := s.rs.Add(*existing); err != nil {
					_, _ = s.cr.Set(prevCR)
					_ = s.rollbackRuleSets(prevRS)
					writeErr(w, http.StatusInternalServerError, err.Error())
					return
				}
			}
		}
		if err := s.applyRuleSets(s.rs.Get()); err != nil {
			_, _ = s.cr.Set(prevCR)
			_ = s.rollbackRuleSets(prevRS)
			_ = s.applyRuleSets(prevRS)
			writeErr(w, http.StatusBadGateway, "apply pack rule sets: "+err.Error())
			return
		}
	}
	if err := s.applyCustomRules(rules); err != nil {
		_, _ = s.cr.Set(prevCR)
		_ = s.rollbackRuleSets(prevRS)
		_ = s.applyRuleSets(prevRS)
		writeErr(w, http.StatusBadGateway, "apply pack: "+err.Error())
		return
	}
	writeArray(w, http.StatusOK, rules.Rules)
}

func findPackPreset(name string) *apitypes.PackPreset {
	for i := range customrules.Presets {
		if customrules.Presets[i].Name == name {
			return &customrules.Presets[i]
		}
	}
	return nil
}

// handleEffectiveRules returns the ordered, layer-labeled view of the effective
// policy (why traffic is allowed/blocked) — the "Routing" tab's data source.
func (s *Server) handleEffectiveRules(w http.ResponseWriter, r *http.Request) {
	if s.rulesView == nil {
		writeErr(w, http.StatusServiceUnavailable, "effective rules not available")
		return
	}
	writeJSON(w, http.StatusOK, s.rulesView.EffectiveRules())
}

func (s *Server) applyCustomRules(rules customrules.Rules) error {
	if s.crApplier == nil {
		return nil
	}
	return s.crApplier.SetCustomRules(rules)
}

// refuseIneffectivePermit rejects a Permit-granting rule on a client instance.
//
// A client may only be stricter (deny) or route around the gateway (direct); it
// cannot widen what the gateway allows. Asking for that is what
// POST /api/permit-requests is for.
func (s *Server) refuseIneffectivePermit(r apitypes.CustomRule) error {
	if s.nodes == nil || s.nodes.LocalMode() != nodes.ModeClient {
		return nil
	}
	grants := r.Permit != nil && *r.Permit
	if r.Permit == nil {
		// Legacy shape: any egress other than block/none implies Permit.
		switch r.Egress {
		case apitypes.CustomEgressProxy, apitypes.CustomEgressNode:
			grants = true
		case "":
			grants = r.Action == apitypes.CustomActionProxy || r.Action == apitypes.CustomActionNode
		}
	}
	if !grants {
		return nil
	}
	return fmt.Errorf(
		"this machine is in client mode: a local rule cannot permit what the gateway denies — " +
			"deny or route-direct here, and ask the gateway's admin with a permit request")
}
