package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/inboundcfg"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func (s *Server) handleGetInbound(w http.ResponseWriter, r *http.Request) {
	if s.inbListen == nil {
		writeErr(w, http.StatusServiceUnavailable, "inbound listen config not available")
		return
	}
	cur := s.inbListen.Get()
	resp := map[string]any{"listen": cur, "resolved": cur.Resolved()}
	// The pending revert belongs in the GET, not only in the PUT's response: a
	// browser that reloaded during the guard window has no other way to learn a
	// countdown is running, and the whole point of the countdown is that
	// somebody has to press confirm.
	if s.inbListenApplier != nil {
		if to, secs, ok := s.inbListenApplier.PendingInboundRevert(); ok {
			resp["revert"] = map[string]any{"to": to, "in_seconds": secs}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSetInbound(w http.ResponseWriter, r *http.Request) {
	if s.inbListen == nil {
		writeErr(w, http.StatusServiceUnavailable, "inbound listen config not available")
		return
	}
	var req struct {
		Listen       string `json:"listen"`
		Port         int    `json:"port"`
		GuardSeconds int    `json:"guard_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	want := apitypes.InboundListen{Listen: req.Listen, Port: req.Port}
	// Both checks run before the store is touched. A rejected request must leave
	// no trace: the store is what the next rebuild reads, so a value written and
	// then refused is a setting that takes effect at the next restart.
	if err := inboundcfg.Validate(want); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.refuseAnonymousExposure(want); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	prev := s.inbListen.Get()
	cfg, err := s.inbListen.Set(want)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := map[string]any{}
	if s.inbListenApplier != nil {
		if req.GuardSeconds > 0 {
			to, err := s.inbListenApplier.SetInboundListenGuarded(cfg, time.Duration(req.GuardSeconds)*time.Second)
			if err != nil {
				_, _ = s.inbListen.Set(prev) // keep the store matching the running plane
				writeErr(w, http.StatusBadGateway, "apply inbound listen: "+err.Error())
				return
			}
			if to != cfg {
				resp["revert"] = map[string]any{"to": to, "in_seconds": req.GuardSeconds}
			}
		} else if err := s.inbListenApplier.SetInboundListen(cfg); err != nil {
			_, _ = s.inbListen.Set(prev)
			writeErr(w, http.StatusBadGateway, "apply inbound listen: "+err.Error())
			return
		}
	}
	resp["listen"] = cfg
	resp["resolved"] = cfg.Resolved()
	writeJSON(w, http.StatusOK, resp)
}

// errAnonymousExposure is returned for a bind that would let anyone who can
// route to this machine use it as a proxy.
//
// This check cannot live in inboundcfg: the rule is about the user registry,
// which a config store has no business importing. And it has to be a refusal
// rather than a warning, because the failure is silent in the worst direction —
// the rebuild succeeds, the console reports the new address, and the machine is
// an open relay. Nothing about the gateway's own behaviour looks wrong
// afterwards; you find out from somebody else's traffic.
var errAnonymousExposure = errors.New(
	"refusing to listen off loopback while no account has a proxy password: that would open " +
		"an anonymous proxy to everyone who can reach this machine. Give an account a proxy " +
		"password first (Settings → Accounts, or `trust-proxy user set <name> --proxy-password`)")

func (s *Server) refuseAnonymousExposure(l apitypes.InboundListen) error {
	if inboundcfg.IsLoopback(l) || s.users == nil {
		return nil
	}
	if len(s.users.ProxyCredentials()) > 0 {
		return nil
	}
	return errAnonymousExposure
}

func (s *Server) handleConfirmInbound(w http.ResponseWriter, r *http.Request) {
	if s.inbListenApplier == nil {
		writeErr(w, http.StatusServiceUnavailable, "inbound listen controller not available")
		return
	}
	s.inbListenApplier.ConfirmInboundListen()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
