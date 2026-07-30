package api

import (
	"net/http"

	"github.com/ivanzzeth/trust-proxy/internal/detectcfg"
	"github.com/ivanzzeth/trust-proxy/internal/dnscfg"
	"github.com/ivanzzeth/trust-proxy/internal/history"
	"github.com/ivanzzeth/trust-proxy/internal/logging"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/proxyscore"
	"github.com/ivanzzeth/trust-proxy/internal/tuncfg"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// handleDefaults reports every domain's built-in configuration.
//
// It exists so a client can render "(default 32 MB)" beside a blank field, and
// offer "restore defaults" in a dialog, without hard-coding the numbers. The
// alternative is a second copy of every default in TypeScript, which is a second
// source of truth: it does not fail loudly when the Go side changes, it just
// starts describing a gateway that no longer exists. /api/proxy-scores already
// works this way — it returns the resolved weights and the formula next to the
// scores, and the console is forbidden from deriving either.
//
// Every value below is read from the package that owns it. Restating even one
// number in this file would reintroduce, one layer lower, exactly the drift the
// endpoint exists to prevent.
func (s *Server) handleDefaults(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apitypes.Defaults{
		TUN:       tuncfg.Resolved(),
		DNS:       dnscfg.Defaults(),
		Detection: detectcfg.Defaults(),
		Inbound:   apitypes.InboundListen{}.Resolved(),
		Retention: apitypes.Retention{
			Log:     logRetentionWire(logging.DefaultOptions()),
			History: historyRetentionWire(history.DefaultOptions()),
		},
		Failover: failoverWire(proxygroups.Failover{}.Resolved()),
		Scoring:  scoringWire(proxyscore.Config{}.Resolved()),
	})
}

// logRetentionWire / historyRetentionWire report each package's own lumberjack
// policy on the shared wire type. Two functions rather than one over `any`
// because logging.Options and history.Options are distinct types that merely
// happen to line up today — a type switch would go silently wrong the moment
// one of them gains a field.
func logRetentionWire(o logging.Options) apitypes.RetentionRule {
	return apitypes.RetentionRule{
		MaxSizeMB: o.MaxSizeMB, MaxBackups: o.MaxBackups,
		MaxAgeDays: o.MaxAgeDays, Compress: &o.Compress,
	}
}

func historyRetentionWire(o history.Options) apitypes.RetentionRule {
	return apitypes.RetentionRule{
		MaxSizeMB: o.MaxSizeMB, MaxBackups: o.MaxBackups,
		MaxAgeDays: o.MaxAgeDays, Compress: &o.Compress,
	}
}
