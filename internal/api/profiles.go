package api

import (
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/logging"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
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

// handleAddProfile snapshots the CURRENT live policy into a named profile.
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
	p := s.snapshotProfile(req.Name)
	saved, err := s.profStore.Add(p)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

// snapshotProfile captures every policy store that ApplyProfile restores. See
// snapshotLivePolicy for the shared capture logic.
func (s *Server) snapshotProfile(name string) apitypes.Profile {
	slot := s.snapshotLivePolicy()
	p := apitypes.Profile{
		Name:        name,
		Whitelist:   slot.Whitelist,
		Blacklist:   slot.Blacklist,
		Directlist:  slot.Directlist,
		CustomRules: slot.CustomRules,
		RuleSets:    slot.RuleSets,
		ProxyGroups: slot.ProxyGroups,
		DNS:         slot.DNS,
		Final:       slot.Final,
	}
	if s.store != nil {
		for _, sub := range s.store.List() {
			if sub.Applied {
				p.SubID = sub.ID
				break
			}
		}
	}
	for _, rs := range slot.RuleSets {
		if rs.Enabled {
			p.RuleSetTags = append(p.RuleSetTags, rs.Tag) // keep legacy field populated
		}
	}
	if s.mode != nil {
		p.Mode = s.mode.Mode()
	}
	return p
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

	var nodes []apitypes.Node
	if p.SubID != "" && s.store != nil {
		if sub, ok := s.store.Get(p.SubID); ok {
			nodes = sub.Nodes
		} else {
			logging.L().Warn().Str("profile", p.ID).Str("subscription", p.SubID).Msg("profile subscription missing, using direct-only")
		}
	}

	in := policyInputs{
		wl:   whitelist.Rules{Domains: p.Whitelist.Domains, IPs: p.Whitelist.IPs, Processes: p.Whitelist.Processes, Devices: p.Whitelist.Devices},
		bl:   blacklist.Rules{Domains: p.Blacklist.Domains, Keywords: p.Blacklist.Keywords, Regexes: p.Blacklist.Regexes, IPs: p.Blacklist.IPs},
		dl:   directlist.Rules{Domains: p.Directlist.Domains, IPs: p.Directlist.IPs},
		cr:   customrules.Rules{Rules: append([]apitypes.CustomRule(nil), p.CustomRules...)},
		sets: s.resolveProfileRuleSets(p),
		pg:   s.resolveProfileProxyGroups(p),
		dns:  s.resolveProfileDNS(p),
	}

	if err := s.profApplier.ApplyProfile(nodes, in.wl, in.bl, in.dl, in.cr, in.sets, in.pg, in.dns, p.Mode, p.Final, ""); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Success: align live stores so other pages reflect the switch. Only
	// write back pg/dns/final when the profile explicitly specified them —
	// otherwise resolveProfile* already fell back to whatever's live, so
	// writing it back would be a no-op at best.
	s.alignLiveStores(in, p.ProxyGroups != nil, p.DNS != nil, p.Final, p.Final != "", "profile activate:")
	if p.SubID != "" && s.store != nil {
		if err := s.store.SetApplied(p.SubID); err != nil {
			logging.L().Warn().Err(err).Msg("profile activate: SetApplied")
		}
	}
	if err := s.profStore.SetActive(p.ID); err != nil {
		logging.L().Warn().Err(err).Msg("profile activate: SetActive")
	}
	logging.L().Info().
		Str("profile", p.Name).Str("id", p.ID).Str("mode", p.Mode).
		Int("wl_domains", len(in.wl.Domains)).Int("wl_ips", len(in.wl.IPs)).
		Int("bl", len(in.bl.Domains)+len(in.bl.IPs)).
		Int("custom_rules", len(in.cr.Rules)).Int("rule_sets", len(in.sets.Sets)).
		Msg("profile activated")
	p, _ = s.profStore.Get(p.ID)
	writeJSON(w, http.StatusOK, p)
}

// resolveProfileRuleSets prefers full RuleSets; falls back to toggling enabled
// flags on the live store from legacy RuleSetTags.
func (s *Server) resolveProfileRuleSets(p apitypes.Profile) ruleset.Sets {
	if len(p.RuleSets) > 0 {
		out := make([]apitypes.RuleSet, 0, len(p.RuleSets))
		for _, rs := range p.RuleSets {
			if rs.Tag == "" {
				continue
			}
			// Fill missing URL from catalog so a restored remote set still downloads.
			if rs.Type == "remote" && rs.URL == "" {
				if entry, ok := ruleset.CatalogByTag(rs.Tag); ok {
					rs.URL = entry.URL
					if rs.Format == "" {
						rs.Format = entry.Format
					}
					if rs.Name == "" {
						rs.Name = entry.Name
					}
					if rs.Role == "" {
						rs.Role = entry.SuggestedRole
					}
				}
			}
			if rs.DownloadDetour == "" {
				rs.DownloadDetour = "direct"
			}
			if rs.UpdateInterval == "" {
				rs.UpdateInterval = "1d"
			}
			out = append(out, rs)
		}
		return ruleset.Sets{Sets: out}
	}
	// Legacy: enable exactly the profile's tags on whatever is currently imported.
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
	return sets
}

func (s *Server) resolveProfileProxyGroups(p apitypes.Profile) proxygroups.Config {
	if p.ProxyGroups == nil {
		if s.pgroups != nil {
			return s.pgroups.Get() // keep current when old profile omitted groups
		}
		return proxygroups.Config{AutoCountry: true, ExcludeCountries: append([]string(nil), proxygroups.DefaultExcludeCountries...)}
	}
	cfg := proxygroups.Config{
		AutoCountry:      p.ProxyGroups.AutoCountry,
		ExcludeCountries: append([]string(nil), p.ProxyGroups.ExcludeCountries...),
	}
	for _, g := range p.ProxyGroups.Groups {
		cfg.Groups = append(cfg.Groups, proxygroups.Group{
			Name: g.Name, Type: g.Type, Filter: g.Filter, Value: g.Value,
			Nodes: append([]string(nil), g.Nodes...),
		})
	}
	return cfg
}

func (s *Server) resolveProfileDNS(p apitypes.Profile) apitypes.DNSConfig {
	if p.DNS != nil {
		return *p.DNS
	}
	if s.dns != nil {
		return s.dns.Get()
	}
	return apitypes.DNSConfig{}
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
