package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/logging"
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
	same := req.Active == from
	if same {
		if req.Active != apitypes.PostureSplit {
			writeJSON(w, http.StatusOK, map[string]any{
				"active":       from,
				"seeded_split": s.posture.Get().Slots[apitypes.PostureSplit].Seeded,
			})
			return
		}
		cur, _ := s.posture.Slot(apitypes.PostureSplit)
		if cur.Seeded {
			writeJSON(w, http.StatusOK, map[string]any{
				"active":       from,
				"seeded_split": true,
			})
			return
		}
		// Already Split but never seeded — fall through and SeedSplit.
	}

	// 1) Snapshot live → leaving slot (preserve Seeded flag on split).
	// When same==true we are reseeding Split in place; still snapshot so a
	// failed apply can roll back to the live policy we had a moment ago.
	leaving := s.snapshotLiveSlot()
	if from == apitypes.PostureSplit {
		prev, _ := s.posture.Slot(apitypes.PostureSplit)
		leaving.Seeded = prev.Seeded || leaving.Seeded
	}
	if err := s.posture.PutSlot(from, leaving); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Rule sets Split wanted but this machine cannot download. Reported to the
	// caller, not only logged: switching to Split and silently getting a policy
	// with a dozen pieces missing is worse than being told, and a log line on a
	// systemd service is not somewhere anyone looks.
	var unreachable []string

	// 2) Load target slot; seed Split on first visit.
	toSlot, err := s.posture.Slot(req.Active)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Active == apitypes.PostureSplit {
		if !toSlot.Seeded {
			toSlot = posture.SeedSplit()
			logging.L().Info().Int("rules", len(toSlot.CustomRules)).
				Int("rule_sets", len(toSlot.RuleSets)).Msg("posture: seeded Split")
		}
		// Point every catalog rule set at a source this machine can actually reach,
		// and disable the ones it cannot.
		//
		// On every switch, not only on the first seed. Split seeds the catalog's
		// *remote* rule sets and sing-box treats a rule set it cannot fetch on initial
		// load as fatal — so this is what stands between a new user behind the GFW and
		// a switch that simply does not work: no exit node means the download cannot go
		// through the proxy either, and the only way out is a mirror. The catalog has
		// carried one for every entry from the beginning.
		//
		// Behind `!Seeded` it was worse than absent. The slot is persisted before the
		// apply that may fail, so a first attempt wrote primary URLs, marked the slot
		// seeded, failed to start the box, and every retry then skipped the resolution
		// and failed identically. Measured on a real machine: five rule sets timing
		// out and no command sequence that could recover.
		changed, unreach := resolveSlotSources(toSlot.RuleSets, s.reachability())
		unreachable = unreach
		if len(unreachable) > 0 {
			logging.L().Warn().Strs("rule_sets", unreachable).
				Msg("posture: no reachable source for these rule sets — disabled; add an exit node and enable them")
		}
		if changed || !toSlot.Seeded {
			if err := s.posture.PutSlot(apitypes.PostureSplit, toSlot); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}

	// Keep a copy of current live for rollback.
	rollback := s.snapshotLiveSlot()
	rollbackPosture := from

	diverged, err := s.applySlot(toSlot, req.Active)
	if err != nil {
		_, _ = s.applySlot(rollback, rollbackPosture)
		writeErr(w, http.StatusBadGateway, "switch posture: "+err.Error())
		return
	}
	if err := s.posture.SetActive(req.Active); err != nil {
		logging.L().Warn().Err(err).Msg("posture SetActive")
	}

	// Split must not run under Clash Global (Global short-circuits before CN direct).
	forcedRule := false
	if req.Active == apitypes.PostureSplit && s.clash != nil {
		if mode, err := s.clash.Mode(); err == nil && strings.EqualFold(mode, "global") {
			if err := s.clash.SetMode("Rule"); err != nil {
				logging.L().Warn().Err(err).Msg("posture: force Clash Rule")
			} else {
				forcedRule = true
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":            req.Active,
		"seeded_split":      s.posture.Get().Slots[apitypes.PostureSplit].Seeded,
		"forced_clash_rule": forcedRule,
		"unreachable_sets":  unreachable,
		// Empty unless a store refused the policy the data plane is now running. Not
		// only logged: live and disk disagreeing means the console shows one policy
		// and the gateway enforces another, until a restart quietly picks the file.
		"diverged_stores": diverged,
	})
}

// snapshotLiveSlot captures the current live policy as a PolicySlot (posture
// swap format). See snapshotLivePolicy for the shared capture logic.
func (s *Server) snapshotLiveSlot() apitypes.PolicySlot {
	return s.snapshotLivePolicy()
}

func (s *Server) applySlot(slot apitypes.PolicySlot, postureName string) ([]string, error) {
	in := policyInputs{
		wl: whitelist.Rules{
			Domains: slot.Whitelist.Domains, IPs: slot.Whitelist.IPs,
			Processes: slot.Whitelist.Processes, Devices: slot.Whitelist.Devices,
		},
		bl: blacklist.Rules{
			Domains: slot.Blacklist.Domains, Keywords: slot.Blacklist.Keywords,
			Regexes: slot.Blacklist.Regexes, IPs: slot.Blacklist.IPs,
		},
		dl:   directlist.Rules{Domains: slot.Directlist.Domains, IPs: slot.Directlist.IPs},
		cr:   customrules.Rules{Rules: append([]apitypes.CustomRule(nil), slot.CustomRules...)},
		sets: ruleset.Sets{Sets: append([]apitypes.RuleSet(nil), slot.RuleSets...)},
	}
	if slot.ProxyGroups != nil {
		in.pg.AutoCountry = slot.ProxyGroups.AutoCountry
		in.pg.ExcludeCountries = append([]string(nil), slot.ProxyGroups.ExcludeCountries...)
		in.pg.Failover = wireFailover(slot.ProxyGroups.Failover)
		in.pg.Scoring = wireScoring(slot.ProxyGroups.Scoring)
		for _, g := range slot.ProxyGroups.Groups {
			in.pg.Groups = append(in.pg.Groups, proxygroups.Group{
				Name: g.Name, Type: g.Type, Filter: g.Filter, Value: g.Value,
				Nodes: append([]string(nil), g.Nodes...),
			})
		}
	} else if s.pgroups != nil {
		in.pg = s.pgroups.Get()
	}
	in.dns = s.resolveSlotDNS(slot)
	final := slot.Final
	if final == "" {
		final = "proxy"
	}
	nodes := s.profApplier.Nodes()

	if err := s.profApplier.ApplyProfile(nodes, in.wl, in.bl, in.dl, in.cr, in.sets, in.pg, in.dns, "", final, postureName); err != nil {
		return nil, err
	}
	// A posture slot swap always replaces every axis (unlike profile
	// activation, which only writes back axes the profile explicitly set).
	diverged := s.alignLiveStores(in, true, true, final, true, "posture:")
	s.notePolicyDivergence(diverged)
	return diverged, nil
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
		logging.L().Warn().Err(err).Msg("posture sync active slot")
	}
}

// resolveSlotSources points a slot's catalog rule sets at a source this machine can
// reach, and reports whether anything changed.
//
// Split out and called on *every* switch to Split rather than only on the first
// seed. The resolution used to sit behind `!toSlot.Seeded`, and the slot is
// persisted before the apply that may fail — so a first attempt wrote a slot full
// of primary URLs, marked it seeded, failed to start the box on them, and every
// retry afterwards skipped the resolution and failed on exactly the same URLs.
// Measured on a real machine: five rule sets timing out, and no sequence of
// commands that could recover. "Retrying cannot help" is the worst property a
// failure can have, because retrying is what everybody does.
//
// Sets whose URL no longer matches the catalog's are left alone, so running this
// repeatedly cannot undo something the operator typed.
func resolveSlotSources(sets []apitypes.RuleSet, reach func(map[string]string) map[string]bool) (changed bool, disabled []string) {
	before := make([]string, len(sets))
	enabled := make([]bool, len(sets))
	for i := range sets {
		before[i], enabled[i] = sets[i].URL, sets[i].Enabled
	}
	disabled = ruleset.ResolveSourcesWith(sets, reach)
	for i := range sets {
		if sets[i].URL != before[i] || sets[i].Enabled != enabled[i] {
			changed = true
		}
	}
	return changed, disabled
}

// reachability returns the probe the source selection should use: the injected one
// when a test has set it, the real network otherwise.
func (s *Server) reachability() func(map[string]string) map[string]bool {
	if s.reach != nil {
		return s.reach
	}
	return func(probe map[string]string) map[string]bool {
		return ruleset.ReachableHosts(probe, 6*time.Second)
	}
}
