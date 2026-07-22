// Package api is the trust-proxy backend's own HTTP API + console host. The
// React console (pkg served at /) talks only to this single origin; connection
// data is proxied from the standard Clash API so the browser never needs the
// Clash secret. Higher-level features (subscriptions) live under /api too.
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/subscription"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
	"github.com/ivanzzeth/trust-proxy/pkg/clash"
)

// Applier applies subscription nodes to the running data plane (gateway.Manager).
type Applier interface {
	Apply(nodes []apitypes.Node) error
}

// Options configures the API server.
type Options struct {
	Addr       string
	Store      *subscription.Store
	Applier    Applier
	Clash      *clash.Client // low-level Clash primitives, proxied to the browser
	ConsoleDir string        // static dir for the React console (served at /)
}

// Server exposes /api/* and serves the console.
type Server struct {
	httpSrv    *http.Server
	store      *subscription.Store
	applier    Applier
	clash      *clash.Client
	consoleDir string
}

// NewServer builds the API server.
func NewServer(o Options) *Server {
	s := &Server{store: o.Store, applier: o.Applier, clash: o.Clash, consoleDir: o.ConsoleDir}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/subscriptions", s.handleListSubs)
	mux.HandleFunc("POST /api/subscriptions", s.handleAddSub)
	mux.HandleFunc("DELETE /api/subscriptions/{id}", s.handleDeleteSub)
	mux.HandleFunc("POST /api/subscriptions/{id}/refresh", s.handleRefreshSub)
	mux.HandleFunc("POST /api/subscriptions/{id}/apply", s.handleApplySub)
	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("DELETE /api/connections/{id}", s.handleKillConn)
	mux.HandleFunc("DELETE /api/connections", s.handleKillAll)
	mux.Handle("/", s.consoleHandler())
	s.httpSrv = &http.Server{Addr: o.Addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return s
}

// Start blocks serving; returns http.ErrServerClosed on Close.
func (s *Server) Start() error { return s.httpSrv.ListenAndServe() }

// Close shuts the server down.
func (s *Server) Close() error { return s.httpSrv.Close() }

// ---- subscriptions --------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListSubs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.List())
}

func (s *Server) handleAddSub(w http.ResponseWriter, r *http.Request) {
	var req apitypes.AddSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.URL == "" && req.Content == "" {
		writeErr(w, http.StatusBadRequest, "url or content is required")
		return
	}
	sub, err := s.store.Add(req.Name, req.URL, req.UserAgent, req.Via, req.Content)
	if err != nil {
		log.Println("subscription add refresh:", err)
	}
	writeJSON(w, http.StatusCreated, sub)
}

func (s *Server) handleDeleteSub(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRefreshSub(w http.ResponseWriter, r *http.Request) {
	sub, err := s.store.Refresh(r.PathValue("id"))
	if err != nil {
		if _, ok := s.store.Get(r.PathValue("id")); !ok {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		log.Println("subscription refresh:", err)
	}
	writeJSON(w, http.StatusOK, sub)
}

func (s *Server) handleApplySub(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "subscription not found")
		return
	}
	if s.applier == nil {
		writeErr(w, http.StatusServiceUnavailable, "gateway applier not available")
		return
	}
	if err := s.applier.Apply(sub.Nodes); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetApplied(sub.ID); err != nil {
		log.Println("mark applied:", err)
	}
	sub, _ = s.store.Get(sub.ID)
	writeJSON(w, http.StatusOK, sub)
}

// ---- connections (proxied from the Clash API) -----------------------------

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	snap, err := s.clash.Connections()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handleKillConn(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	if err := s.clash.CloseConnection(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleKillAll(w http.ResponseWriter, r *http.Request) {
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "clash api not available")
		return
	}
	if err := s.clash.CloseAllConnections(); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- console static host --------------------------------------------------

// consoleHandler serves the React console with SPA fallback. If the build is
// missing it returns a short hint instead of a 404.
func (s *Server) consoleHandler() http.Handler {
	fileSrv := http.FileServer(http.Dir(s.consoleDir))
	index := filepath.Join(s.consoleDir, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(index); err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("trust-proxy console not built.\nRun: make console\n"))
			return
		}
		if p := filepath.Join(s.consoleDir, filepath.Clean(r.URL.Path)); r.URL.Path != "/" {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				fileSrv.ServeHTTP(w, r)
				return
			}
		}
		http.ServeFile(w, r, index) // SPA fallback
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, apitypes.ErrorResponse{Error: msg})
}
