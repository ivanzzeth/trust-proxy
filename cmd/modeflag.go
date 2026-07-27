package cmd

import (
	"path/filepath"

	"github.com/ivanzzeth/trust-proxy/internal/modecfg"
)

// modeStore is what resolveMode needs from the capture-mode store, kept narrow so
// the resolution rule can be tested without a filesystem.
type modeStore interface {
	Get() string
	Set(string) (string, error)
}

// resolveMode decides which capture mode this run starts in.
//
// No flag: the stored mode, like every other policy axis. An explicit flag: that
// mode, and it is written to the store so the two can never disagree afterwards.
//
// The recording is the part worth being careful about. Before this, `--mode`
// defaulted to "manual" and was applied on every boot, so the stored mode did not
// exist and switching to TUN from the console silently expired at the next
// restart. A flag that merely overrode the store on each boot would be the same
// bug with the sign flipped — the console switch would apply, work, and then be
// undone by the next restart, which is harder to diagnose, not easier. So the flag
// is a one-time instruction, not a standing one, and after the first boot the
// store is the only source of truth.
func resolveMode(flag string, store modeStore) (string, error) {
	if flag == "" {
		return store.Get(), nil
	}
	if err := modecfg.Validate(flag); err != nil {
		return "", err
	}
	return store.Set(flag)
}

// seedMode records the capture mode `install` was asked for and returns the mode
// the daemon will come up in.
//
// An empty want means "whatever this machine is already set to", which is the
// case that matters: it is what `install.sh` and the desktop Update button run,
// and while the mode lived in the service definition's argument list that phrase
// was a lie — rewriting the list dropped the argument and the gateway came back
// in manual, still healthy, no longer capturing anything.
func seedMode(dataDir, want string) (string, error) {
	store, err := modecfg.NewStore(filepath.Join(dataDir, "mode.json"))
	if err != nil {
		return "", err
	}
	if want == "" {
		return store.Get(), nil
	}
	return store.Set(want)
}
