package cmd

import (
	"fmt"
	"os"
	"path/filepath"
)

// One config, in the data directory.
//
// `-c` used to default to configs/config.json — a *repo-relative* path. That only
// means anything when you run from a checkout, so every other way of running the
// gateway had to invent its own location: the desktop app picked
// <data>/config.json and reimplemented "seed a default on first run" in Rust. Two
// conventions and two copies of the same logic, which is how a CLI daemon and a
// desktop app end up on different configs (and different capture modes) on the
// same machine.
//
// Now the config lives beside the data it belongs to: <data>/config.json, seeded
// on first run from the default compiled into the binary. `-c` remains an explicit
// override for anything else (configs/config.tun.json, a pinned deployment file).

// defaultConfig is the shipped sing-box config, injected from main via
// SetDefaultConfig (go:embed lives in the root package, where configs/ is
// reachable). There is exactly one such file in the repo: configs/config.json.
var defaultConfig []byte

// SetDefaultConfig hands the embedded default config to the CLI.
func SetDefaultConfig(b []byte) { defaultConfig = b }

// legacyConfigPath is where the old default pointed, relative to the working
// directory.
//
// It is *reported*, never used. Seeding from it silently made a privileged
// command depend on where it was run from: the release tarball ships a
// configs/ directory, so `cd trust-proxy_v1.2.3_linux_amd64 && sudo
// ./trust-proxy install` seeded from that copy rather than the one compiled in,
// and any other directory that happens to contain configs/config.json would have
// been adopted too. The reason it existed — a developer's edits in a checkout —
// is served just as well by saying so and letting them pass -c.
const legacyConfigPath = "configs/config.json"

// resolveConfig returns the config path to use, seeding <data>/config.json on
// first run. An explicit -c is returned untouched.
func resolveConfig(explicit, dataDir string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	path := filepath.Join(dataDir, "config.json")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if len(defaultConfig) == 0 {
		return "", fmt.Errorf("no config at %s and no default to seed it from", path)
	}
	seed := defaultConfig
	// Say it rather than doing it: a config sitting in the working directory is
	// either irrelevant (the release tarball's copy) or somebody's edited one, and
	// only they can tell which.
	if _, err := os.Stat(legacyConfigPath); err == nil {
		fmt.Printf("note: ignoring %s in the current directory; pass -c %s if that is the one you want\n",
			legacyConfigPath, legacyConfigPath)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return "", fmt.Errorf("seed %s: %w", path, err)
	}
	// Printed, not logged: this happens before the logging stack is up, and
	// "which config am I running" is the first thing anyone asks.
	fmt.Printf("seeded %s from the built-in default\n", path)
	return path, nil
}
