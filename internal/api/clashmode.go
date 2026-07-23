package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// clashModes are the routing modes we expose. Rule = normal (security floor +
// whitelist default-deny). Global = default-deny OFF, unlisted traffic egresses
// via the proxy group (the floor — blacklist/threat/process+device gates — stays
// on). We deliberately do NOT expose Clash "Direct" (it would bypass the proxy
// exit entirely, i.e. leak everything direct). The gateway injects a matching
// clash_mode:"Global" route rule; switching is live (Clash PATCH /configs, no
// data-plane rebuild).
var clashModes = []string{"Rule", "Global"}

func (s *Server) handleGetClashMode(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	mode, err := s.clash.Mode()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode, "modes": clashModes})
}

func (s *Server) handleSetClashMode(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Mode == "" {
		writeErr(w, http.StatusBadRequest, "mode is required")
		return
	}
	// Accept only Rule / Global (case-insensitive); reject Direct and anything
	// else so the browser can't route everything direct (leak) via this toggle.
	valid := ""
	for _, m := range clashModes {
		if strings.EqualFold(m, req.Mode) {
			valid = m
			break
		}
	}
	if valid == "" {
		writeErr(w, http.StatusBadRequest, "mode must be Rule or Global")
		return
	}
	if err := s.clash.SetMode(valid); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": valid})
}
