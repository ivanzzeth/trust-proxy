package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	if s.profStore == nil {
		writeErr(w, http.StatusServiceUnavailable, "profiles not available")
		return
	}
	writeJSON(w, http.StatusOK, s.profStore.List())
}

// handleAddProfile snapshots the CURRENT live policy (applied subscription +
// whitelist + enabled rule-set tags + capture mode) into a named profile.
func (s *Server) handleAddProfile(w http.ResponseWriter, r *http.Request) {
	if s.profStore == nil {
		writeErr(w, http.StatusServiceUnavailable, "profiles not available")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	p := apitypes.Profile{Name: req.Name}
	if s.store != nil {
		for _, sub := range s.store.List() {
			if sub.Applied {
				p.SubID = sub.ID
				break
			}
		}
	}
	if s.wl != nil {
		wl := s.wl.Get()
		p.Whitelist = apitypes.Rules{Domains: wl.Domains, IPs: wl.IPs, Processes: wl.Processes, Devices: wl.Devices}
	}
	if s.rs != nil {
		for _, rs := range s.rs.Get().Sets {
			if rs.Enabled {
				p.RuleSetTags = append(p.RuleSetTags, rs.Tag)
			}
		}
	}
	if s.mode != nil {
		p.Mode = s.mode.Mode()
	}
	saved, err := s.profStore.Add(p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

// handleActivateProfile does a single atomic rebuild to the profile's policy,
// then (only on success) aligns the live stores to match.
func (s *Server) handleActivateProfile(w http.ResponseWriter, r *http.Request) {
	if s.profStore == nil || s.profApplier == nil {
		writeErr(w, http.StatusServiceUnavailable, "profiles not available")
		return
	}
	p, ok := s.profStore.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "profile not found")
		return
	}

	// Resolve nodes from the referenced subscription (missing => direct-only).
	var nodes []apitypes.Node
	if p.SubID != "" && s.store != nil {
		if sub, ok := s.store.Get(p.SubID); ok {
			nodes = sub.Nodes
		} else {
			log.Printf("profile %q: subscription %q missing, using direct-only", p.ID, p.SubID)
		}
	}

	// Resolve rule sets: enable exactly the profile's tags, disable the rest.
	want := map[string]bool{}
	for _, t := range p.RuleSetTags {
		want[t] = true
	}
	var sets ruleset.Sets
	if s.rs != nil {
		sets = s.rs.Get()
		for i := range sets.Sets {
			sets.Sets[i].Enabled = want[sets.Sets[i].Tag]
		}
	}

	wl := whitelist.Rules{Domains: p.Whitelist.Domains, IPs: p.Whitelist.IPs, Processes: p.Whitelist.Processes, Devices: p.Whitelist.Devices}

	if err := s.profApplier.ApplyProfile(nodes, wl, sets, p.Mode); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Success: align the live stores so the other pages reflect the switch.
	if s.rs != nil {
		for _, rsdef := range sets.Sets {
			if _, err := s.rs.SetEnabled(rsdef.Tag, rsdef.Enabled); err != nil {
				log.Println("profile activate: rs SetEnabled:", err)
			}
		}
	}
	if s.wl != nil {
		if _, err := s.wl.Set(wl); err != nil {
			log.Println("profile activate: wl Set:", err)
		}
	}
	if p.SubID != "" && s.store != nil {
		if err := s.store.SetApplied(p.SubID); err != nil {
			log.Println("profile activate: SetApplied:", err)
		}
	}
	if err := s.profStore.SetActive(p.ID); err != nil {
		log.Println("profile activate: SetActive:", err)
	}
	p, _ = s.profStore.Get(p.ID)
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	if s.profStore == nil {
		writeErr(w, http.StatusServiceUnavailable, "profiles not available")
		return
	}
	if err := s.profStore.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
