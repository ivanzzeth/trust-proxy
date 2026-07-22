package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// These proxy the standard Clash API through our backend so the browser stays
// single-origin and never needs the Clash secret.

func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	b, err := s.clash.Proxies()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	b, err := s.clash.GetRaw("/rules")
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (s *Server) handleSelectProxy(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	var req struct {
		Group string `json:"group"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Group == "" || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "group and name are required")
		return
	}
	if err := s.clash.SelectProxy(req.Group, req.Name); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleProxyDelay(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	timeout, _ := strconv.Atoi(r.URL.Query().Get("timeout"))
	b, err := s.clash.Delay(r.PathValue("name"), r.URL.Query().Get("url"), timeout)
	if err != nil {
		// A failed latency test (timeout/unreachable) is a normal result, not a
		// server error — surface it so the UI can show "timeout".
		writeJSON(w, http.StatusOK, map[string]any{"delay": 0, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// handleLogs streams the Clash /logs WebSocket to the browser as Server-Sent
// Events (simpler on the client than proxying a WebSocket, single-origin).
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	_ = s.clash.StreamLogs(r.Context(), r.URL.Query().Get("level"), func(raw []byte) error {
		if _, err := fmt.Fprintf(w, "data: %s\n\n", raw); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	})
}
