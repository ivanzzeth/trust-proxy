package cmd

import (
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/detectcfg"
)

func newDetStore(t *testing.T, dir string) *detectcfg.Store {
	t.Helper()
	s, err := detectcfg.NewStore(filepath.Join(dir, "detection.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// `serve --auto-block=false` used to be inert: the engine field was set and then
// ApplyConfig(store.Get()) overwrote it a few lines later. The flag has to reach
// the config the engine actually runs with, and it has to reach the file too —
// otherwise the run has disposal off while the console reads it on.
//
// Teeth: drop the `cfg.AutoBlock = flagValue; store.Set(cfg)` body from
// resolveAutoBlock and both assertions below fail.
func TestAutoBlockFlagOverridesStore(t *testing.T) {
	dir := t.TempDir()
	store := newDetStore(t, dir)
	if !store.Get().AutoBlock {
		t.Fatalf("precondition: default AutoBlock should be true")
	}

	cfg, err := resolveAutoBlock(store, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoBlock {
		t.Fatalf("engine would run with disposal on despite --auto-block=false")
	}
	if store.Get().AutoBlock {
		t.Fatalf("flag did not reach the store; the console would still show it on")
	}
}

// The flag's default is true and so is the stored setting, so the value alone
// cannot say "the operator asked for this". An untyped flag must not resurrect a
// setting the operator turned off in the console.
func TestAutoBlockUntypedFlagDoesNotOverrideStore(t *testing.T) {
	dir := t.TempDir()
	store := newDetStore(t, dir)

	c := store.Get()
	c.AutoBlock = false
	if _, err := store.Set(c); err != nil {
		t.Fatal(err)
	}

	// flagSet=false, flagValue=true — exactly what a plain `serve` produces.
	cfg, err := resolveAutoBlock(store, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoBlock {
		t.Fatalf("plain `serve` turned disposal back on")
	}
	if store.Get().AutoBlock {
		t.Fatalf("plain `serve` rewrote the stored setting")
	}
}

// Explicitly typing the value that is already stored is a no-op, not a rewrite.
func TestAutoBlockFlagMatchingStoreIsNoop(t *testing.T) {
	dir := t.TempDir()
	store := newDetStore(t, dir)

	cfg, err := resolveAutoBlock(store, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AutoBlock || !store.Get().AutoBlock {
		t.Fatalf("--auto-block=true against a true store should leave it true: cfg=%v store=%v",
			cfg.AutoBlock, store.Get().AutoBlock)
	}
}

// The flag is registered on serveCmd, so Flags().Changed("auto-block") in RunE
// has something to look at. A rename would make the override silently stop
// working with no compile error.
func TestAutoBlockFlagIsRegistered(t *testing.T) {
	if serveCmd.Flags().Lookup("auto-block") == nil {
		t.Fatalf("serve has no --auto-block flag; serveAutoBlockSet can never be true")
	}
}
