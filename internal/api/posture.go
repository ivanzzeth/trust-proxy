package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/finalroute"
	"github.com/ivanzzeth/trust-proxy/internal/posture"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleGetPosture(w http.ResponseWriter, r *http.Request) {
	if s.posture == nil {
		writeErr(w, http.StatusServiceUnavailable, "posture not available")
		return
	}
	st := s.posture.Get()
	split := st.Slots[apitypes.PostureSplit]
	active := st.Active
	if s.profApplier != nil {
		if p := s.profApplier.Posture(); apitypes.ValidPosture(p) {
			active = p
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active":       active,
		"seeded_split": split.Seeded,
	})
}

func (s *Server) handleSetPosture(w http.ResponseWriter, r *http.Request) {
	if s.posture == nil || s.profApplier == nil {
		writeErr(w, http.StatusServiceUnavailable, "posture not available")
		return
	}
	var req struct {
		Active string `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !apitypes.ValidPosture(req.Active) {
		writeErr(w, http.StatusBadRequest, "active must be strict or split")
		return
	}

	from := s.posture.Active()
	if p := s.profApplier.Posture(); apitypes.ValidPosture(p) {
		from = p
	}
	if req.Active == from {
		writeJSON(w, http.StatusOK, map[string]any{
			"active":       from,
			"seeded_split": s.posture.Get().Slots[apitypes.PostureSplit].Seeded,
		})
		return
	}

	// 1) Snapshot live → leaving slot (preserve Seeded flag on split).
	leaving := s.snapshotLiveSlot()
	if from == apitypes.PostureSplit {
		prev, _ := s.posture.Slot(apitypes.PostureSplit)
		leaving.Seeded = prev.Seeded || leaving.Seeded
	}
	if err := s.posture.PutSlot(from, leaving); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 2) Load target slot; seed Split on first visit.
	toSlot, err := s.posture.Slot(req.Active)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Active == apitypes.PostureSplit && !toSlot.Seeded {
		toSlot = posture.SeedSplit()
		if err := s.posture.PutSlot(apitypes.PostureSplit, toSlot); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		log.Printf("posture: seeded Split with %d pack rule(s), %d rule-set(s)", len(toSlot.CustomRules), len(toSlot.RuleSets))
	}

	// Keep a copy of current live for rollback.
	rollback := s.snapshotLiveSlot()
	rollbackPosture := from

	if err := s.applySlot(toSlot, req.Active); err != nil {
		_ = s.applySlot(rollback, rollbackPosture)
		writeErr(w, http.StatusBadGateway, "switch posture: "+err.Error())
		return
	}
	if err := s.posture.SetActive(req.Active); err != nil {
		log.Println("posture SetActive:", err)
	}

	// Split must not run under Clash Global (Global short-circuits before CN direct).
	forcedRule := false
	if req.Active == apitypes.PostureSplit && s.clash != nil {
		if mode, err := s.clash.Mode(); err == nil && strings.EqualFold(mode, "global") {
			if err := s.clash.SetMode("Rule"); err != nil {
				log.Println("posture: force Clash Rule:", err)
			} else {
				forcedRule = true
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":            req.Active,
		"seeded_split":      s.posture.Get().Slots[apitypes.PostureSplit].Seeded,
		"forced_clash_rule": forcedRule,
	})
}

func (s *Server) snapshotLiveSlot() apitypes.PolicySlot {
	slot := apitypes.PolicySlot{Final: "proxy"}
	if s.wl != nil {
		wl := s.wl.Get()
		slot.Whitelist = apitypes.Rules{Domains: wl.Domains, IPs: wl.IPs, Processes: wl.Processes, Devices: wl.Devices}
	}
	if s.bl != nil {
		bl := s.bl.Get()
		slot.Blacklist = apitypes.Blacklist{Domains: bl.Domains, Keywords: bl.Keywords, Regexes: bl.Regexes, IPs: bl.IPs}
	}
	if s.dl != nil {
		dl := s.dl.Get()
		slot.Directlist = apitypes.DirectList{Domains: dl.Domains, IPs: dl.IPs}
	}
	if s.cr != nil {
		slot.CustomRules = append([]apitypes.CustomRule(nil), s.cr.Get().Rules...)
	}
	if s.rs != nil {
		slot.RuleSets = append([]apitypes.RuleSet(nil), s.rs.Get().Sets...)
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
		slot.ProxyGroups = &out
	}
	if s.dns != nil {
		d := s.dns.Get()
		cp := d
		slot.DNS = &cp
	}
	if s.final != nil {
		slot.Final = s.final.Get().Outbound
	} else if s.finalApplier != nil {
		slot.Final = s.finalApplier.Final()
	}
	return slot
}

func (s *Server) applySlot(slot apitypes.PolicySlot, postureName string) error {
	wl := whitelist.Rules{
		Domains: slot.Whitelist.Domains, IPs: slot.Whitelist.IPs,
		Processes: slot.Whitelist.Processes, Devices: slot.Whitelist.Devices,
	}
	bl := blacklist.Rules{
		Domains: slot.Blacklist.Domains, Keywords: slot.Blacklist.Keywords,
		Regexes: slot.Blacklist.Regexes, IPs: slot.Blacklist.IPs,
	}
	dl := directlist.Rules{Domains: slot.Directlist.Domains, IPs: slot.Directlist.IPs}
	cr := customrules.Rules{Rules: append([]apitypes.CustomRule(nil), slot.CustomRules...)}
	sets := ruleset.Sets{Sets: append([]apitypes.RuleSet(nil), slot.RuleSets...)}
	pg := proxygroups.Config{}
	if slot.ProxyGroups != nil {
		pg.AutoCountry = slot.ProxyGroups.AutoCountry
		pg.ExcludeCountries = append([]string(nil), slot.ProxyGroups.ExcludeCountries...)
		for _, g := range slot.ProxyGroups.Groups {
			pg.Groups = append(pg.Groups, proxygroups.Group{
				Name: g.Name, Type: g.Type, Filter: g.Filter, Value: g.Value,
				Nodes: append([]string(nil), g.Nodes...),
			})
		}
	} else if s.pgroups != nil {
		pg = s.pgroups.Get()
	}
	dns := apitypes.DNSConfig{}
	if slot.DNS != nil {
		dns = *slot.DNS
	}
	final := slot.Final
	if final == "" {
		final = "proxy"
	}
	nodes := s.profApplier.Nodes()

	if err := s.profApplier.ApplyProfile(nodes, wl, bl, dl, cr, sets, pg, dns, "", final, postureName); err != nil {
		return err
	}

	// Align live stores after successful rebuild.
	if s.wl != nil {
		if _, err := s.wl.Set(wl); err != nil {
			log.Println("posture: wl Set:", err)
		}
	}
	if s.bl != nil {
		if _, err := s.bl.Set(bl); err != nil {
			log.Println("posture: bl Set:", err)
		}
	}
	if s.dl != nil {
		if _, err := s.dl.Set(dl); err != nil {
			log.Println("posture: dl Set:", err)
		}
	}
	if s.cr != nil {
		if _, err := s.cr.Set(cr); err != nil {
			log.Println("posture: cr Set:", err)
		}
	}
	if s.rs != nil {
		if _, err := s.rs.Set(sets); err != nil {
			log.Println("posture: rs Set:", err)
		}
	}
	if s.pgroups != nil {
		if _, err := s.pgroups.Set(pg); err != nil {
			log.Println("posture: pg Set:", err)
		}
	}
	if s.dns != nil {
		if _, err := s.dns.Set(dns); err != nil {
			log.Println("posture: dns Set:", err)
		}
	}
	if s.final != nil {
		if _, err := s.final.Set(finalroute.Config{Outbound: final}); err != nil {
			log.Println("posture: final Set:", err)
		}
	}
	return nil
}

// SyncActivePostureSlot writes the current live policy into the active posture
// slot (called once at serve start).
func (s *Server) SyncActivePostureSlot() {
	s.syncActiveSlotFromLive()
}

// syncActiveSlotFromLive writes the current live policy into the active posture
// slot so the inactive slot stays the only stale side.
func (s *Server) syncActiveSlotFromLive() {
	if s.posture == nil {
		return
	}
	active := s.posture.Active()
	slot := s.snapshotLiveSlot()
	if active == apitypes.PostureSplit {
		prev, _ := s.posture.Slot(apitypes.PostureSplit)
		slot.Seeded = prev.Seeded
		// If somehow active=split but never seeded, mark seeded so we don't
		// wipe user live state on next switch-away/back.
		if !slot.Seeded && (len(slot.CustomRules) > 0 || len(slot.RuleSets) > 0) {
			slot.Seeded = true
		}
	}
	if err := s.posture.PutSlot(active, slot); err != nil {
		log.Println("posture sync active slot:", err)
	}
}
