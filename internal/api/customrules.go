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

func (s *Server) applyCustomRules(rules customrules.Rules) error {
	if s.crApplier == nil {
		return nil
	}
	return s.crApplier.SetCustomRules(rules)
}
