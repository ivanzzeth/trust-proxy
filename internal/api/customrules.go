package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleListCustomRules(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	writeJSON(w, http.StatusOK, s.cr.Get())
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
	writeJSON(w, http.StatusCreated, rules)
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
	writeJSON(w, http.StatusOK, rules)
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
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleMoveCustomRule(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	prev := s.cr.Get()
	var req struct {
		Dir int `json:"dir"` // <0 up (higher priority), >0 down
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Dir == 0 {
		writeErr(w, http.StatusBadRequest, "dir must be a non-zero integer")
		return
	}
	rules, err := s.cr.Move(r.PathValue("id"), req.Dir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyCustomRules(rules); err != nil {
		_, _ = s.cr.Set(prev)
		writeErr(w, http.StatusBadGateway, "apply custom rule: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rules)
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
			if !validRole(role) {
				writeErr(w, http.StatusBadRequest, "invalid role for "+prs.CatalogTag+": "+role)
				return
			}
			rs := apitypes.RuleSet{
				Tag: entry.Tag, Name: entry.Name, Type: "remote", Format: entry.Format,
				URL: entry.URL, DownloadDetour: "direct", UpdateInterval: "1d",
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

	writeJSON(w, http.StatusCreated, map[string]any{
		"rules":     out,
		"rule_sets": packRS,
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
			if _, err := s.rs.SetEnabled(prs.CatalogTag, req.Enabled); err != nil {
				_, _ = s.cr.Set(prevCR)
				_ = s.rollbackRuleSets(prevRS)
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
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
	writeJSON(w, http.StatusOK, rules)
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
			if _, err := s.rs.Remove(prs.CatalogTag); err != nil {
				_, _ = s.cr.Set(prevCR)
				_ = s.rollbackRuleSets(prevRS)
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
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
	writeJSON(w, http.StatusOK, rules)
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
