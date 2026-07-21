// Package api is the trust-proxy backend's own HTTP API (the "high-level"
// surface, distinct from the standard Clash API). The SDK's high-level client
// (pkg/client) talks to this; the low-level client (pkg/clash) talks straight
// to the Clash API.
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/subscription"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Server exposes /api/* backed by the subscription store.
type Server struct {
	httpSrv *http.Server
	store   *subscription.Store
}

// NewServer builds the API server bound to addr.
func NewServer(addr string, store *subscription.Store) *Server {
	s := &Server{store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/subscriptions", s.handleListSubs)
	mux.HandleFunc("POST /api/subscriptions", s.handleAddSub)
	mux.HandleFunc("DELETE /api/subscriptions/{id}", s.handleDeleteSub)
	mux.HandleFunc("POST /api/subscriptions/{id}/refresh", s.handleRefreshSub)
	s.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// Start blocks serving; returns http.ErrServerClosed on Close.
func (s *Server) Start() error { return s.httpSrv.ListenAndServe() }

// Close shuts the server down.
func (s *Server) Close() error { return s.httpSrv.Close() }

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
	if req.URL == "" {
		writeErr(w, http.StatusBadRequest, "url is required")
		return
	}
	sub, err := s.store.Add(req.Name, req.URL)
	if err != nil {
		// Add still persists the subscription even if the first refresh fails;
		// return 201 with LastError populated so the client sees the reason.
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, apitypes.ErrorResponse{Error: msg})
}
