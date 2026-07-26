package api

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/nodes"
)

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeArray(w, http.StatusOK, []nodes.Public{})
		return
	}
	// The local gateway is listed too, so the console shows one uniform list and a
	// console-only user can point at remote gateways without "this machine" being a
	// special case somewhere else in the UI.
	s.nodes.EnsureLocal(localGatewayName())
	writeArray(w, http.StatusOK, s.nodes.List())
}

// handlePatchNode edits a gateway entry: enable/disable, use-as-exit and the
// credential for it, or the local entry's mode.
//
// Changing anything that affects egress re-derives the exit outbounds and
// hot-reloads them — a switch that only takes effect at the next restart is a
// switch people do not trust.
func (s *Server) handlePatchNode(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeErr(w, http.StatusServiceUnavailable, "node registry not available")
		return
	}
	var req nodes.PatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	out, err := s.nodes.Patch(r.PathValue("id"), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.syncGatewayExits(); err != nil {
		writeErr(w, http.StatusBadGateway, "apply gateway exits: "+err.Error())
		return
	}
	// Switching this machine between gateway and client changes whether it enforces
	// egress policy at all, so it has to reach the data plane now.
	if req.Mode != nil && s.cmApplier != nil {
		if err := s.cmApplier.SetClientMode(s.nodes.LocalMode() == nodes.ModeClient); err != nil {
			writeErr(w, http.StatusBadGateway, "apply client mode: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// syncGatewayExits pushes the derived exit outbounds to the data plane.
func (s *Server) syncGatewayExits() error {
	if s.gwApplier == nil || s.nodes == nil {
		return nil
	}
	return s.gwApplier.SetGatewayExits(s.nodes.ExitNodes())
}

// localGatewayName is what the self-entry is called until somebody renames it.
func localGatewayName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "this machine"
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
			pr.Out.Header.Del("Authorization")
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
