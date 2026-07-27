package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	if s.dns == nil {
		writeErr(w, http.StatusServiceUnavailable, "dns config not available")
		return
	}
	writeJSON(w, http.StatusOK, s.dns.Get())
}

func (s *Server) handleSetDNS(w http.ResponseWriter, r *http.Request) {
	if s.dns == nil {
		writeErr(w, http.StatusServiceUnavailable, "dns config not available")
		return
	}
	var req apitypes.DNSConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	// A DNS rule may only name a rule set that exists.
	//
	// dnscfg validates server tags and Final against the declared servers, and had
	// no way to check this one: the rule sets live in another store. So the mistake
	// travelled — the gateway self-heals a dangling reference now, but silently
	// dropping the rule the operator just wrote is a worse answer than refusing it
	// here, where the message can name the tag and list what is available.
	if s.rs != nil {
		known := map[string]bool{}
		for _, rs := range s.rs.Get().Sets {
			if rs.Enabled {
				known[rs.Tag] = true
			}
		}
		for i, r := range req.Rules {
			for _, tag := range r.RuleSet {
				if !known[tag] {
					writeErr(w, http.StatusBadRequest, fmt.Sprintf(
						"rules[%d] names rule set %q, which is not imported or not enabled", i, tag))
					return
				}
			}
		}
	}

	prev := s.dns.Get()
	cfg, err := s.dns.Set(req) // validates
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.dnsApplier != nil {
		if err := s.dnsApplier.SetDNS(cfg); err != nil {
			_, _ = s.dns.Set(prev) // roll back the store to match the running plane
			writeErr(w, http.StatusBadGateway, "apply dns: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, cfg)
}
