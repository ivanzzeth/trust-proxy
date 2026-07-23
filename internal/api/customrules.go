package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/customrules"
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

// ---- Allow packs (named groups of custom rules) --------------------------

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
	}
	if name == "" || len(rules) == 0 {
		writeErr(w, http.StatusBadRequest, "a catalog name or a non-empty {name, rules} is required")
		return
	}
	prev := s.cr.Get()
	var out customrules.Rules
	for _, rule := range rules {
		rule.ID = ""
		rule.Pack = name
		rule.Enabled = true
		var err error
		if out, err = s.cr.Add(rule); err != nil {
			_, _ = s.cr.Set(prev)
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := s.applyCustomRules(out); err != nil {
		_, _ = s.cr.Set(prev)
		writeErr(w, http.StatusBadGateway, "apply pack: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handlePatchPack(w http.ResponseWriter, r *http.Request) {
	if s.cr == nil {
		writeErr(w, http.StatusServiceUnavailable, "custom rules not available")
		return
	}
	prev := s.cr.Get()
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	rules, err := s.cr.SetPackEnabled(r.PathValue("name"), req.Enabled)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyCustomRules(rules); err != nil {
		_, _ = s.cr.Set(prev)
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
	prev := s.cr.Get()
	rules, err := s.cr.RemovePack(r.PathValue("name"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyCustomRules(rules); err != nil {
		_, _ = s.cr.Set(prev)
		writeErr(w, http.StatusBadGateway, "apply pack: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rules)
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
