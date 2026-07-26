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

// legacyConfigPath is where the old default pointed. If a checkout has one and
// the data directory does not, that file is what the user has been editing — so
// it becomes the seed rather than the shipped default, and their tweaks survive
// the change instead of being silently ignored.
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
	seed, from := defaultConfig, "built-in default"
	if data, err := os.ReadFile(legacyConfigPath); err == nil {
		seed, from = data, legacyConfigPath
	}
	if len(seed) == 0 {
		return "", fmt.Errorf("no config at %s and no default to seed it from", path)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, seed, 0o644); err != nil {
		return "", fmt.Errorf("seed %s: %w", path, err)
	}
	// Printed, not logged: this happens before the logging stack is up, and
	// "which config am I running" is the first thing anyone asks.
	fmt.Printf("seeded %s from %s\n", path, from)
	return path, nil
}
