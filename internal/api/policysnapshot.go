package api

import (
	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/finalroute"
	"github.com/ivanzzeth/trust-proxy/internal/logging"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// snapshotLivePolicy captures every policy store that ApplyProfile restores —
// the fields shared by both a posture PolicySlot (snapshotLiveSlot) and a
// saved Profile (snapshotProfile), which otherwise differ only in their extra
// metadata (Seeded vs ID/Name/SubID/Mode/...).
func (s *Server) snapshotLivePolicy() apitypes.PolicySlot {
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

// policyInputs is the store-shaped form of a PolicySlot/Profile's policy
// fields, ready to hand to ProfileApplier.ApplyProfile.
type policyInputs struct {
	wl   whitelist.Rules
	bl   blacklist.Rules
	dl   directlist.Rules
	cr   customrules.Rules
	sets ruleset.Sets
	pg   proxygroups.Config
	dns  apitypes.DNSConfig
}

// alignLiveStores writes an already-applied policy back into each live store
// so other API pages reflect the switch. Best-effort: a failed Set here
// doesn't undo the (already successful) ApplyProfile — it only logs. pg/dns/
// final are only written when their setPG/setDNS/setFinal flag is true, so
// callers that resolved them from a fallback (rather than an explicit slot/
// profile value) can skip overwriting the store with what's already there.
func (s *Server) alignLiveStores(in policyInputs, setPG, setDNS bool, final string, setFinal bool, logPrefix string) {
	if s.rs != nil {
		if _, err := s.rs.Set(in.sets); err != nil {
			logging.L().Warn().Err(err).Str("op", logPrefix).Str("store", "rs").Msg("align live store failed")
		}
	}
	go ruleset.WarmPermitCache(in.sets, nil) // keep detection's permit-role index in sync
	if s.wl != nil {
		if _, err := s.wl.Set(in.wl); err != nil {
			logging.L().Warn().Err(err).Str("op", logPrefix).Str("store", "wl").Msg("align live store failed")
		}
	}
	if s.bl != nil {
		if _, err := s.bl.Set(in.bl); err != nil {
			logging.L().Warn().Err(err).Str("op", logPrefix).Str("store", "bl").Msg("align live store failed")
		}
	}
	if s.dl != nil {
		if _, err := s.dl.Set(in.dl); err != nil {
			logging.L().Warn().Err(err).Str("op", logPrefix).Str("store", "dl").Msg("align live store failed")
		}
	}
	if s.cr != nil {
		if _, err := s.cr.Set(in.cr); err != nil {
			logging.L().Warn().Err(err).Str("op", logPrefix).Str("store", "cr").Msg("align live store failed")
		}
	}
	if setPG && s.pgroups != nil {
		if _, err := s.pgroups.Set(in.pg); err != nil {
			logging.L().Warn().Err(err).Str("op", logPrefix).Str("store", "pg").Msg("align live store failed")
		}
	}
	if setDNS && s.dns != nil {
		if _, err := s.dns.Set(in.dns); err != nil {
			logging.L().Warn().Err(err).Str("op", logPrefix).Str("store", "dns").Msg("align live store failed")
		}
	}
	if setFinal && s.final != nil {
		if _, err := s.final.Set(finalroute.Config{Outbound: final}); err != nil {
			logging.L().Warn().Err(err).Str("op", logPrefix).Str("store", "final").Msg("align live store failed")
		}
	}
}
