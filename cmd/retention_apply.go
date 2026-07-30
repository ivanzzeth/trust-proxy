package cmd

import (
	"errors"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/history"
	"github.com/ivanzzeth/trust-proxy/internal/logging"
	"github.com/ivanzzeth/trust-proxy/internal/retentioncfg"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// retentionApplier puts a stored retention policy into force on the two
// lumberjacks that are actually running.
//
// It lives here rather than on gateway.Manager because neither half is the
// gateway's: the daemon log belongs to internal/logging (a process-wide stack)
// and the history file to internal/history (a store the Manager never sees).
// This is the composition root — the only place that holds both.
type retentionApplier struct{ hist *history.Store }

// SetRetention applies both halves, reporting what failed rather than stopping
// at the first error. A partial apply is the realistic outcome here: a
// foreground run has no rotating log file at all, and that must not stop the
// history policy — the caller would roll the whole store back over a half the
// operator never asked about.
func (a retentionApplier) SetRetention(r apitypes.Retention) error {
	var errs []error
	if err := logging.SetRotation(logging.Options{
		MaxSizeMB:  r.Log.MaxSizeMB,
		MaxBackups: r.Log.MaxBackups,
		MaxAgeDays: r.Log.MaxAgeDays,
		Compress:   r.Log.CompressOr(logging.DefaultOptions().Compress),
	}); err != nil && !errors.Is(err, logging.ErrNoRotatingLog) {
		errs = append(errs, err)
	}
	if a.hist != nil {
		if err := a.hist.SetRetention(history.Options{
			MaxSizeMB:  r.History.MaxSizeMB,
			MaxBackups: r.History.MaxBackups,
			MaxAgeDays: r.History.MaxAgeDays,
			Compress:   r.History.CompressOr(history.DefaultOptions().Compress),
		}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// serveRetention is the store opened by loadServeRetention, kept so runServe
// hands the API the same object the flags were reconciled against rather than a
// second one reading the same file.
var serveRetention *retentioncfg.Store

// loadServeRetention opens the retention store and folds the eight `serve`
// flags into it, then rewrites the flag variables so everything downstream
// builds from one resolved policy.
//
// The direction matters and is the same one resolveAutoBlock established: the
// store wins, and a flag only overrides it when somebody actually typed it
// (Flags().Changed). Letting the flag win unconditionally would reintroduce the
// bug with the sign flipped — the console's change would apply, then be undone
// at the next boot by a default nobody chose. The flags' own defaults are not
// evidence of intent: --log-compress defaults to true, so its value alone can
// never distinguish "the operator asked for compression" from "the operator
// said nothing".
func loadServeRetention(cmd *cobra.Command, dataDir string) error {
	store, err := retentioncfg.NewStore(filepath.Join(dataDir, "retention.json"))
	if err != nil {
		return err
	}
	cfg, err := resolveRetention(store, flagsChanged(cmd,
		"log-max-size", "log-keep", "log-max-age", "log-compress",
		"history-max-size", "history-keep", "history-max-age", "history-compress"),
		apitypes.Retention{
			Log: apitypes.RetentionRule{
				MaxSizeMB: serveLogMaxMB, MaxBackups: serveLogKeep,
				MaxAgeDays: serveLogMaxAge, Compress: &serveLogCompress,
			},
			History: apitypes.RetentionRule{
				MaxSizeMB: serveHistoryMaxMB, MaxBackups: serveHistoryKeep,
				MaxAgeDays: serveHistoryMaxAge, Compress: &serveHistoryCompress,
			},
		})
	if err != nil {
		return err
	}
	serveRetention = store

	log := cfg.Log
	logDef := logging.DefaultOptions()
	serveLogMaxMB, serveLogKeep = unsetOrDefault(log.MaxSizeMB, logDef.MaxSizeMB), unsetOrDefault(log.MaxBackups, logDef.MaxBackups)
	serveLogMaxAge, serveLogCompress = log.MaxAgeDays, log.CompressOr(logDef.Compress)

	hist := cfg.History
	histDef := history.DefaultOptions()
	serveHistoryMaxMB, serveHistoryKeep = unsetOrDefault(hist.MaxSizeMB, histDef.MaxSizeMB), unsetOrDefault(hist.MaxBackups, histDef.MaxBackups)
	serveHistoryMaxAge, serveHistoryCompress = hist.MaxAgeDays, hist.CompressOr(histDef.Compress)
	return nil
}

// resolveRetention merges typed flags into the stored policy, persisting the
// result so the file and the running process never disagree.
func resolveRetention(store *retentioncfg.Store, changed map[string]bool, flags apitypes.Retention) (apitypes.Retention, error) {
	cfg := store.Get()
	dirty := false
	set := func(name string, apply func()) {
		if changed[name] {
			apply()
			dirty = true
		}
	}
	set("log-max-size", func() { cfg.Log.MaxSizeMB = flags.Log.MaxSizeMB })
	set("log-keep", func() { cfg.Log.MaxBackups = flags.Log.MaxBackups })
	set("log-max-age", func() { cfg.Log.MaxAgeDays = flags.Log.MaxAgeDays })
	set("log-compress", func() { cfg.Log.Compress = flags.Log.Compress })
	set("history-max-size", func() { cfg.History.MaxSizeMB = flags.History.MaxSizeMB })
	set("history-keep", func() { cfg.History.MaxBackups = flags.History.MaxBackups })
	set("history-max-age", func() { cfg.History.MaxAgeDays = flags.History.MaxAgeDays })
	set("history-compress", func() { cfg.History.Compress = flags.History.Compress })
	if !dirty {
		return cfg, nil
	}
	return store.Set(cfg)
}

// flagsChanged reports which of names the operator actually typed. A flag that
// is not registered reports false rather than panicking: `serve` is not the only
// caller of this package and a missing flag must not take the gateway down.
func flagsChanged(cmd *cobra.Command, names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = cmd.Flags().Changed(n)
	}
	return out
}

// unsetOrDefault resolves the "unset" spelling. Deliberately not runtime.go's
// orDefault, which folds negatives into the default as well: here -1 is the
// operator asking for no rotation at all and has to survive.
func unsetOrDefault(got, def int) int {
	if got == 0 {
		return def
	}
	return got
}

// There is deliberately no applyStoredRetention: loadServeRetention runs before
// either lumberjack is constructed, so both are *built* from the resolved
// policy. An after-the-fact correction would leave the first seconds of every
// boot running under a policy nobody chose, and would be a second place where
// the file and the process can disagree.
