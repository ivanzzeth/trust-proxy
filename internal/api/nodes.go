package api

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.nodes.List())
}

func (s *Server) handleAddNode(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeErr(w, http.StatusServiceUnavailable, "node registry not available")
		return
	}
	var req struct {
		Name  string `json:"name"`
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	n, err := s.nodes.Add(req.Name, req.URL, req.Token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, n)
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeErr(w, http.StatusServiceUnavailable, "node registry not available")
		return
	}
	if err := s.nodes.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleNodeProxy reverse-proxies /api/nodes/{id}/{rest...} to the registered
// probe's /api/{rest}, injecting its bearer token server-side. Streams (SSE)
// pass through via FlushInterval=-1.
func (s *Server) handleNodeProxy(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeErr(w, http.StatusServiceUnavailable, "node registry not available")
		return
	}
	n, ok := s.nodes.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	target, err := url.Parse(n.URL)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "bad node url: "+err.Error())
		return
	}
	rest := r.PathValue("rest")
	token := n.Token
	proxy := &httputil.ReverseProxy{
		FlushInterval: -1, // stream SSE / long-poll immediately
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = "/api/" + strings.TrimPrefix(rest, "/")
			pr.Out.URL.RawQuery = r.URL.RawQuery
			pr.Out.Host = target.Host
			if token != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+token)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeErr(w, http.StatusBadGateway, "node unreachable: "+err.Error())
		},
	}
	proxy.ServeHTTP(w, r)
}
