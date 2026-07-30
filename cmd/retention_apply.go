package cmd

import (
	"errors"

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

// applyStoredRetention puts the persisted policy into force at startup.
//
// Startup needs this because the store is read after logging.Setup has already
// built the stack from flags: without this call the file on disk would be the
// setting the console shows and the flags would be the setting in force, which
// is the two-writers-one-of-them-forgetful shape this whole round exists to
// remove. A failure is logged, not fatal — retention is not worth refusing to
// boot over.
func applyStoredRetention(store *retentioncfg.Store, hist *history.Store) {
	if store == nil {
		return
	}
	cfg := store.Get()
	// An untouched store has no opinion, and no opinion must not overwrite one.
	// Until the eight serve flags fold into this store, they are still the only
	// way some machines set retention; applying an all-zero policy over them
	// would reset those machines to the defaults at the next boot — a setting
	// nobody touched changing itself, which is the whole bug this round removes.
	if cfg == (apitypes.Retention{}) {
		return
	}
	if err := (retentionApplier{hist: hist}).SetRetention(cfg); err != nil {
		logging.L().Warn().Err(err).Msg("could not apply the stored retention policy")
	}
}
