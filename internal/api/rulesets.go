package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func validRole(r string) bool {
	switch r {
	case apitypes.RuleRoleBlock, apitypes.RuleRoleAllowDirect, apitypes.RuleRoleAllowProxy:
		return true
	}
	return false
}

// formatFromURL infers binary/source from the .srs/.json extension.
func formatFromURL(u string) string {
	if strings.HasSuffix(u, ".json") {
		return "source"
	}
	return "binary" // .srs and unknown default to binary
}

func (s *Server) handleListRuleSets(w http.ResponseWriter, r *http.Request) {
	if s.rs == nil {
		writeErr(w, http.StatusServiceUnavailable, "rule sets not available")
		return
	}
	writeJSON(w, http.StatusOK, s.rs.Get())
}

func (s *Server) handleRuleSetCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ruleset.Catalog)
}

func (s *Server) handleAddRuleSet(w http.ResponseWriter, r *http.Request) {
	if s.rs == nil {
		writeErr(w, http.StatusServiceUnavailable, "rule sets not available")
		return
	}
	var req apitypes.AddRuleSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	var rs apitypes.RuleSet
	if req.CatalogTag != "" {
		var entry *apitypes.RuleSetCatalogEntry
		for i := range ruleset.Catalog {
			if ruleset.Catalog[i].Tag == req.CatalogTag {
				entry = &ruleset.Catalog[i]
				break
			}
		}
		if entry == nil {
			writeErr(w, http.StatusBadRequest, "unknown catalog tag: "+req.CatalogTag)
			return
		}
		url := entry.URL
		if req.Mirror {
			url = entry.Mirror
		}
		role := entry.SuggestedRole
		if req.Role != "" {
			role = req.Role
		}
		rs = apitypes.RuleSet{Tag: entry.Tag, Name: entry.Name, Type: "remote", Format: entry.Format, URL: url, Role: role, Enabled: true}
	} else {
		rs = apitypes.RuleSet{
			Tag: req.Tag, Name: req.Name, Type: req.Type, Format: req.Format,
			URL: req.URL, Path: req.Path, Role: req.Role, Enabled: true,
		}
		if rs.Type == "" {
			rs.Type = "remote"
		}
		if rs.Name == "" {
			rs.Name = rs.Tag
		}
	}
	if rs.Tag == "" {
		writeErr(w, http.StatusBadRequest, "tag is required")
		return
	}
	if !validRole(rs.Role) {
		writeErr(w, http.StatusBadRequest, "role must be block | allow-direct | allow-proxy")
		return
	}
	if rs.Type == "remote" {
		if rs.URL == "" {
			writeErr(w, http.StatusBadRequest, "url is required for a remote rule set")
			return
		}
		if rs.Format == "" {
			rs.Format = formatFromURL(rs.URL)
		}
	} else {
		if rs.Path == "" {
			writeErr(w, http.StatusBadRequest, "path is required for a local rule set")
			return
		}
		if rs.Format == "" {
			rs.Format = formatFromURL(rs.Path)
		}
	}

	sets, err := s.rs.Add(rs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyRuleSets(sets); err != nil {
		// Roll back the just-added set so the store matches the running plane.
		sets, _ = s.rs.Remove(rs.Tag)
		writeErr(w, http.StatusBadGateway, "apply rule set: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sets)
}

func (s *Server) handlePatchRuleSet(w http.ResponseWriter, r *http.Request) {
	if s.rs == nil {
		writeErr(w, http.StatusServiceUnavailable, "rule sets not available")
		return
	}
	tag := r.PathValue("tag")
	var req apitypes.PatchRuleSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	var (
		sets ruleset.Sets
		err  error
	)
	if req.Role != nil {
		if !validRole(*req.Role) {
			writeErr(w, http.StatusBadRequest, "role must be block | allow-direct | allow-proxy")
			return
		}
		sets, err = s.rs.SetRole(tag, *req.Role)
	}
	if err == nil && req.Enabled != nil {
		sets, err = s.rs.SetEnabled(tag, *req.Enabled)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyRuleSets(sets); err != nil {
		writeErr(w, http.StatusBadGateway, "apply rule set: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sets)
}

func (s *Server) handleDeleteRuleSet(w http.ResponseWriter, r *http.Request) {
	if s.rs == nil {
		writeErr(w, http.StatusServiceUnavailable, "rule sets not available")
		return
	}
	sets, err := s.rs.Remove(r.PathValue("tag"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyRuleSets(sets); err != nil {
		writeErr(w, http.StatusBadGateway, "apply rule set: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sets)
}

func (s *Server) applyRuleSets(sets ruleset.Sets) error {
	if s.rsApplier == nil {
		return nil
	}
	return s.rsApplier.SetRuleSets(sets)
}
