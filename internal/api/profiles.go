package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/finalroute"
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
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

// snapshotProfile captures every policy store that ApplyProfile restores.
func (s *Server) snapshotProfile(name string) apitypes.Profile {
	p := apitypes.Profile{Name: name}
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
	if s.bl != nil {
		bl := s.bl.Get()
		p.Blacklist = apitypes.Blacklist{Domains: bl.Domains, Keywords: bl.Keywords, Regexes: bl.Regexes, IPs: bl.IPs}
	}
	if s.dl != nil {
		dl := s.dl.Get()
		p.Directlist = apitypes.DirectList{Domains: dl.Domains, IPs: dl.IPs}
	}
	if s.cr != nil {
		cr := s.cr.Get()
		p.CustomRules = append([]apitypes.CustomRule(nil), cr.Rules...)
	}
	if s.rs != nil {
		sets := s.rs.Get().Sets
		p.RuleSets = append([]apitypes.RuleSet(nil), sets...)
		for _, rs := range sets {
			if rs.Enabled {
				p.RuleSetTags = append(p.RuleSetTags, rs.Tag) // keep legacy field populated
			}
		}
	}
	if s.pgroups != nil {
		pg := s.pgroups.Get()
		out := apitypes.ProxyGroupsConfig{
			AutoCountry:      pg.AutoCountry,
			ExcludeCountries: append([]string(nil), pg.ExcludeCountries...),
		}
		for _, g := range pg.Groups {
			out.Groups = append(out.Groups, apitypes.ProxyGroup{
				Name: g.Name, Type: g.Type, Filter: g.Filter, Value: g.Value,
				Nodes: append([]string(nil), g.Nodes...),
			})
		}
		p.ProxyGroups = &out
	}
	if s.dns != nil {
		d := s.dns.Get()
		cp := d
		p.DNS = &cp
	}
	if s.final != nil {
		p.Final = s.final.Get().Outbound
	} else if s.finalApplier != nil {
		p.Final = s.finalApplier.Final()
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
			log.Printf("profile %q: subscription %q missing, using direct-only", p.ID, p.SubID)
		}
	}

	sets := s.resolveProfileRuleSets(p)
	wl := whitelist.Rules{Domains: p.Whitelist.Domains, IPs: p.Whitelist.IPs, Processes: p.Whitelist.Processes, Devices: p.Whitelist.Devices}
	bl := blacklist.Rules{Domains: p.Blacklist.Domains, Keywords: p.Blacklist.Keywords, Regexes: p.Blacklist.Regexes, IPs: p.Blacklist.IPs}
	dl := directlist.Rules{Domains: p.Directlist.Domains, IPs: p.Directlist.IPs}
	cr := customrules.Rules{Rules: append([]apitypes.CustomRule(nil), p.CustomRules...)}
	pg := s.resolveProfileProxyGroups(p)
	dns := s.resolveProfileDNS(p)

	if err := s.profApplier.ApplyProfile(nodes, wl, bl, dl, cr, sets, pg, dns, p.Mode, p.Final); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Success: align live stores so other pages reflect the switch.
	if s.rs != nil {
		if _, err := s.rs.Set(sets); err != nil {
			log.Println("profile activate: rs Set:", err)
		}
	}
	if s.wl != nil {
		if _, err := s.wl.Set(wl); err != nil {
			log.Println("profile activate: wl Set:", err)
		}
	}
	if s.bl != nil {
		if _, err := s.bl.Set(bl); err != nil {
			log.Println("profile activate: bl Set:", err)
		}
	}
	if s.dl != nil {
		if _, err := s.dl.Set(dl); err != nil {
			log.Println("profile activate: dl Set:", err)
		}
	}
	if s.cr != nil {
		if _, err := s.cr.Set(cr); err != nil {
			log.Println("profile activate: cr Set:", err)
		}
	}
	if s.pgroups != nil && p.ProxyGroups != nil {
		if _, err := s.pgroups.Set(pg); err != nil {
			log.Println("profile activate: pg Set:", err)
		}
	}
	if s.dns != nil && p.DNS != nil {
		if _, err := s.dns.Set(dns); err != nil {
			log.Println("profile activate: dns Set:", err)
		}
	}
	if s.final != nil && p.Final != "" {
		if _, err := s.final.Set(finalroute.Config{Outbound: p.Final}); err != nil {
			log.Println("profile activate: final Set:", err)
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
	log.Printf("profile activated %q (%s): wl=%d/%d bl=%d cr=%d rs=%d mode=%s",
		p.Name, p.ID, len(wl.Domains), len(wl.IPs), len(bl.Domains)+len(bl.IPs), len(cr.Rules), len(sets.Sets), p.Mode)
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
