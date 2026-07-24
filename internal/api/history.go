package api

import (
	"net/http"
	"strconv"

	"github.com/ivanzzeth/trust-proxy/internal/history"
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
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	host := q.Get("q")
	if host == "" {
		host = q.Get("host") // back-compat
	}
	// ?page=1 returns {items,total,limit,offset}; bare array kept for old clients
	// that only pass host/limit (CLI / early SDK).
	if q.Get("page") == "1" || q.Has("offset") {
		items, total := s.history.RecentPage(limit, offset, host)
		if limit <= 0 || limit > 2000 {
			limit = 50
		}
		if offset < 0 {
			offset = 0
		}
		writeJSON(w, http.StatusOK, history.Page{Items: items, Total: total, Limit: limit, Offset: offset})
		return
	}
	writeJSON(w, http.StatusOK, s.history.Recent(limit, host))
}
