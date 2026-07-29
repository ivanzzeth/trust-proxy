package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/doctor"
)

type installDoctorRequest struct {
	Yes bool `json:"yes"`
}

// handleInstallNftables attempts to install nftables userspace package when
// missing. This is best-effort and intentionally narrow to reduce blast
// radius.
func (s *Server) handleInstallNftables(w http.ResponseWriter, r *http.Request) {
	// Only the gateway process should ever serve this endpoint; it runs as a
	// system service and can ask the package manager. access control is
	// enforced by the auth middleware.
	var req installDoctorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	rep, err := doctor.InstallNftables(context.Background(), doctor.InstallNftablesRequest{Yes: req.Yes})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
