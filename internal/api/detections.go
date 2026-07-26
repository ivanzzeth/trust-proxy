package api

import (
	"net/http"
	"strconv"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
)

func (s *Server) handleDetections(w http.ResponseWriter, r *http.Request) {
	if s.detections == nil {
		writeJSON(w, http.StatusOK, detect.Page{Items: []detect.Detection{}, Limit: 50})
		return
	}
	q := detect.Query{
		Q: r.URL.Query().Get("q"),
	}
	if k := r.URL.Query().Get("kind"); k != "" {
		q.Kind = detect.Kind(k)
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Offset = n
		}
	}
	page := s.detections.Query(q)
	if scope := s.scopeUser(r); scope != "" {
		page.Items = scopeDetections(page.Items, scope)
		page.Total = len(page.Items)
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleDetectionsStats(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"alerts_24h":  0,
		"blocked_24h": 0,
		"banned_24h":  0,
		"by_kind":     map[string]int{},
	}
	if s.detections != nil {
		st := s.detections.Stats()
		out["alerts_24h"] = st.Alerts24h
		out["blocked_24h"] = st.Blocked24h
		out["banned_24h"] = st.Banned24h
		out["by_kind"] = st.ByKind
	}
	if s.detect != nil {
		d, ip := s.detect.ThreatCounts()
		out["intel_domains"] = d
		out["intel_ips"] = ip
	} else {
		out["intel_domains"] = 0
		out["intel_ips"] = 0
	}
	writeJSON(w, http.StatusOK, out)
}
