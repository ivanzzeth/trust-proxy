package api

import (
	"net/http"
	"strconv"
)

func (s *Server) handleHistoryStats(w http.ResponseWriter, r *http.Request) {
	if s.history == nil {
		writeErr(w, http.StatusServiceUnavailable, "history not available")
		return
	}
	writeJSON(w, http.StatusOK, s.history.Stats())
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if s.history == nil {
		writeErr(w, http.StatusServiceUnavailable, "history not available")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	writeJSON(w, http.StatusOK, s.history.Recent(limit, r.URL.Query().Get("host")))
}
