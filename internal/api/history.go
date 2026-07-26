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
	// One shape, always: {items,total,limit,offset}.
	//
	// This used to return a bare array unless ?page=1 was passed, and the SDK
	// decoded into a map — so `history ls` failed with "cannot unmarshal array into
	// map" against its own backend. An endpoint with two shapes is a trap for every
	// client, and the docker e2e caught this one only because it asserts on real
	// output.
	items, total := s.history.RecentPage(limit, offset, host)
	if scope := s.scopeUser(r); scope != "" {
		// Filtering after the page read costs a shorter page for a client, which is
		// the honest trade: the alternative is pushing an identity into the store's
		// read path, and the store must not decide who may see what.
		items = scopeHistory(items, scope)
		total = len(items)
	}
	if limit <= 0 || limit > 2000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	writeJSON(w, http.StatusOK, history.Page{Items: items, Total: total, Limit: limit, Offset: offset})
}
