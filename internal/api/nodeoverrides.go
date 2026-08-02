package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// NodeOverridesApplier hot-reloads the disabled-tag set (gateway.Manager).
type NodeOverridesApplier interface {
	SetDisabledNodes(tags []string) error
}

func (s *Server) handleGetNodeOverrides(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.nodeOverridesView())
}

func (s *Server) handlePutNodeOverrides(w http.ResponseWriter, r *http.Request) {
	if s.nodeOverrides == nil {
		writeErr(w, http.StatusServiceUnavailable, "node overrides not available")
		return
	}
	var req apitypes.NodeOverridesPatch
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	prev := s.nodeOverrides.Disabled()
	var next []string
	var err error
	switch {
	case req.Disabled != nil:
		next, err = s.nodeOverrides.SetDisabled(*req.Disabled)
	case strings.TrimSpace(req.Disable) != "":
		next, err = s.nodeOverrides.SetTag(req.Disable, true)
	case strings.TrimSpace(req.Enable) != "":
		next, err = s.nodeOverrides.SetTag(req.Enable, false)
	default:
		writeErr(w, http.StatusBadRequest, "set disabled, disable, or enable")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.applyNodeOverrides(prev, next); err != nil {
		writeErr(w, http.StatusBadGateway, "apply node overrides: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.nodeOverridesView())
}

func (s *Server) handleDisableNode(w http.ResponseWriter, r *http.Request) {
	s.setNodeTag(w, r, true)
}

func (s *Server) handleEnableNode(w http.ResponseWriter, r *http.Request) {
	s.setNodeTag(w, r, false)
}

func (s *Server) setNodeTag(w http.ResponseWriter, r *http.Request, disabled bool) {
	if s.nodeOverrides == nil {
		writeErr(w, http.StatusServiceUnavailable, "node overrides not available")
		return
	}
	var req apitypes.NodeTagBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Tag) == "" {
		writeErr(w, http.StatusBadRequest, "tag is required")
		return
	}
	prev := s.nodeOverrides.Disabled()
	next, err := s.nodeOverrides.SetTag(req.Tag, disabled)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.applyNodeOverrides(prev, next); err != nil {
		writeErr(w, http.StatusBadGateway, "apply node overrides: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.nodeOverridesView())
}

func (s *Server) applyNodeOverrides(prev, next []string) error {
	if s.noApplier == nil {
		return nil
	}
	if err := s.noApplier.SetDisabledNodes(next); err != nil {
		_ = s.nodeOverrides.Restore(prev)
		return err
	}
	return nil
}

func (s *Server) nodeOverridesView() apitypes.NodeOverrides {
	out := apitypes.NodeOverrides{
		Disabled: []string{},
		Junk:     []apitypes.JunkNode{},
		Nodes:    []apitypes.NodeMember{},
	}
	disabled := map[string]bool{}
	if s.nodeOverrides != nil {
		out.Disabled = s.nodeOverrides.Disabled()
		for _, t := range out.Disabled {
			disabled[t] = true
		}
	}
	if s.store == nil {
		return out
	}
	for _, n := range s.store.AppliedNodes() {
		tag := n.Tag
		if tag == "" {
			tag = "node"
		}
		server := n.Server
		port := n.Port
		member := apitypes.NodeMember{
			Tag: tag, Protocol: n.Protocol, Server: server, Port: port,
			Status: apitypes.NodeStatusLive,
		}
		if junk, reason := proxygroups.IsJunkNode(tag, server, port); junk {
			member.Status = apitypes.NodeStatusJunk
			member.Reason = reason
			out.Junk = append(out.Junk, apitypes.JunkNode{
				Tag: tag, Reason: reason, Server: server, Port: port, Protocol: n.Protocol,
			})
		} else if disabled[tag] {
			member.Status = apitypes.NodeStatusDisabled
		}
		out.Nodes = append(out.Nodes, member)
	}
	sort.Slice(out.Junk, func(i, j int) bool { return out.Junk[i].Tag < out.Junk[j].Tag })
	return out
}
