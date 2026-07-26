package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/proxygen"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// One-click self-hosted exit. The console used to just tell people to run
// `trust-proxy proxy gen` in a terminal and paste the client node back, which
// only works if you have a shell open and get the two halves from the *same*
// run — generate twice and the client node no longer matches the running server.
// Here the gateway generates once and returns both halves plus the script that
// deploys the server one.
//
// Generation is pure: nothing is stored and no traffic is touched. The response
// carries freshly minted secrets, so it rides the same bearer auth as the rest
// of /api and is never cached.

func (s *Server) handleProxyProtocols(w http.ResponseWriter, r *http.Request) {
	writeArray(w, http.StatusOK, proxygen.Protocols)
}

func (s *Server) handleProxyGen(w http.ResponseWriter, r *http.Request) {
	var req apitypes.ProxyGenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Type = strings.TrimSpace(strings.ToLower(req.Type))
	if req.Type == "" {
		writeErr(w, http.StatusBadRequest, "type is required; one of: "+strings.Join(proxygen.Protocols, ", "))
		return
	}
	// Generate rejects unknown types too, but saying it here keeps the error a 400
	// with the list instead of a bare "unsupported".
	known := false
	for _, p := range proxygen.Protocols {
		if p == req.Type {
			known = true
			break
		}
	}
	if !known && req.Type != "ss" {
		writeErr(w, http.StatusBadRequest, "unsupported type "+req.Type+"; one of: "+strings.Join(proxygen.Protocols, ", "))
		return
	}
	// The CLI may print a YOUR_SERVER_IP placeholder for a human to fill in; an
	// API caller is feeding a machine, and a node pointing at a placeholder would
	// be imported and then quietly fail to dial.
	req.Server = strings.TrimSpace(req.Server)
	if err := validServerHost(req.Server); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if req.Port < 1 || req.Port > 65535 {
		writeErr(w, http.StatusBadRequest, "port must be 1-65535")
		return
	}
	req.SNI = strings.TrimSpace(req.SNI)
	req.Name = strings.TrimSpace(req.Name)

	opts := proxygen.Options{Type: req.Type, Server: req.Server, Port: req.Port, SNI: req.SNI, Name: req.Name}
	res, err := proxygen.Generate(opts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, apitypes.ProxyGenResult{
		Server:        res.Server,
		Client:        res.Client,
		Share:         res.Share,
		GenCommand:    proxygen.GenCommand(opts),
		InstallScript: proxygen.InstallScript(res.Server, ""),
	})
}

// validServerHost accepts an IP or a hostname — not a URL, not host:port, and
// nothing with shell or shape surprises, since the value is pasted into a node
// definition and into a deploy script.
func validServerHost(h string) error {
	if h == "" {
		return errString("server is required (the address clients dial)")
	}
	if strings.ContainsAny(h, " \t\r\n/\\?#'\"") || strings.Contains(h, "://") {
		return errString("server must be a bare IP or hostname")
	}
	if ip := net.ParseIP(h); ip != nil {
		return nil
	}
	if strings.Contains(h, ":") {
		return errString("server must not include a port (use the port field)")
	}
	if len(h) > 253 {
		return errString("server is too long")
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" || len(label) > 63 {
			return errString("server is not a valid hostname")
		}
		for _, r := range label {
			if !(r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return errString("server is not a valid hostname")
			}
		}
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }
