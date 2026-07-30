package cmd

import (
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/retentioncfg"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func newRetStore(t *testing.T) *retentioncfg.Store {
	t.Helper()
	s, err := retentioncfg.NewStore(filepath.Join(t.TempDir(), "retention.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// flagRetention is what `serve`'s flag variables hold: every field populated,
// including the two Compress defaults that are true. Only the `changed` map can
// say which of them the operator actually typed.
func flagRetention(compress bool) apitypes.Retention {
	c := compress
	return apitypes.Retention{
		Log:     apitypes.RetentionRule{MaxSizeMB: 32, MaxBackups: 3, MaxAgeDays: 0, Compress: &c},
		History: apitypes.RetentionRule{MaxSizeMB: 128, MaxBackups: 3, MaxAgeDays: 0, Compress: &c},
	}
}

// A typed flag overrides the store and is written back, so the file and the
// running process never disagree.
//
// Teeth: drop the store.Set at the end of resolveRetention and the second
// assertion fails.
func TestRetentionTypedFlagOverridesStore(t *testing.T) {
	store := newRetStore(t)
	cfg, err := resolveRetention(store, map[string]bool{"log-max-size": true}, flagRetention(true))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.MaxSizeMB != 32 {
		t.Fatalf("typed --log-max-size did not reach the resolved config: %+v", cfg.Log)
	}
	if store.Get().Log.MaxSizeMB != 32 {
		t.Fatalf("typed flag did not reach the store; the console would show the old value")
	}
	// Untyped siblings must stay unset, not be frozen at today's defaults: a
	// store full of "32" cannot later follow a change to the built-in default.
	if store.Get().Log.MaxBackups != 0 || store.Get().History.MaxSizeMB != 0 {
		t.Fatalf("untyped flags leaked into the store: %+v", store.Get())
	}
}

// A plain `serve` must not rewrite anything. This is the exact shape of the
// auto-block bug: the flag defaults are indistinguishable from a real choice, so
// letting them win would undo the console's setting at every boot.
//
// Teeth: change the `if changed[name]` guard in resolveRetention to
// unconditional and both assertions fail.
func TestRetentionUntypedFlagsDoNotOverrideStore(t *testing.T) {
	store := newRetStore(t)
	off := false
	if _, err := store.Set(apitypes.Retention{
		Log: apitypes.RetentionRule{MaxSizeMB: 8, Compress: &off},
	}); err != nil {
		t.Fatal(err)
	}

	cfg, err := resolveRetention(store, map[string]bool{}, flagRetention(true))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.MaxSizeMB != 8 {
		t.Fatalf("plain `serve` overrode the stored size: %+v", cfg.Log)
	}
	// The compress default is true and the operator stored false. If the flag's
	// value alone were treated as intent, gzip would come back on at every boot.
	if cfg.Log.Compress == nil || *cfg.Log.Compress {
		t.Fatalf("plain `serve` turned compression back on: %v", cfg.Log.Compress)
	}
}

// An explicitly typed --log-compress=false must be recorded as false rather than
// collapsing into "unset" — the tri-state has to survive the flag layer too.
func TestRetentionTypedCompressFalseIsRecorded(t *testing.T) {
	store := newRetStore(t)
	cfg, err := resolveRetention(store, map[string]bool{"log-compress": true}, flagRetention(false))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.Compress == nil || *cfg.Log.Compress {
		t.Fatalf("typed --log-compress=false did not stick: %v", cfg.Log.Compress)
	}
	if got := store.Get().Log.Compress; got == nil || *got {
		t.Fatalf("typed --log-compress=false did not reach the store: %v", got)
	}
}

// No-rotation is spelled -1 and must survive resolution: unsetOrDefault folding
// it into the default would silently re-enable rotation on a machine that asked
// for none.
func TestRetentionNoRotationSurvives(t *testing.T) {
	if got := unsetOrDefault(retentioncfg.NoRotation, 32); got != retentioncfg.NoRotation {
		t.Fatalf("no-rotation collapsed into the default: %d", got)
	}
	if got := unsetOrDefault(0, 32); got != 32 {
		t.Fatalf("unset must resolve to the default: %d", got)
	}
}

// All eight flags are registered on serveCmd, so Flags().Changed has something
// to look at. A rename would make the override silently stop working with no
// compile error — the same trap TestAutoBlockFlagIsRegistered guards.
func TestRetentionFlagsAreRegistered(t *testing.T) {
	for _, n := range []string{
		"log-max-size", "log-keep", "log-max-age", "log-compress",
		"history-max-size", "history-keep", "history-max-age", "history-compress",
	} {
		if serveCmd.Flags().Lookup(n) == nil {
			t.Fatalf("serve has no --%s flag; loadServeRetention can never see it typed", n)
		}
	}
}

// The CLI's own `retention set` flags must match the serve flags one for one, or
// the two ways to set the same thing start describing different settings.
func TestRetentionCLIFlagsMatchServeFlags(t *testing.T) {
	for _, n := range []string{
		"log-max-size", "log-keep", "log-max-age", "log-compress",
		"history-max-size", "history-keep", "history-max-age", "history-compress",
	} {
		if retentionSetCmd.Flags().Lookup(n) == nil {
			t.Fatalf("`retention set` has no --%s; it cannot set what `serve` can", n)
		}
	}
}
