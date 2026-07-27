// Package modecfg persists the capture mode: manual | system | tun.
//
// It exists because this was the one policy axis with no store. Every other axis
// — posture, final, blacklist, quarantine, no-proxy, custom rules — is written to
// a file and read back by `serve` on boot. The capture mode came from a CLI flag
// and was written nowhere, so its only durable record was the `--mode` argument
// in the launchd plist / systemd unit. Two consequences, both silent:
//
//   - Switching to TUN from the console or the CLI worked, and stopped working at
//     the next restart. Gateway healthy, console green, nothing being captured.
//   - Any re-install without an explicit --mode rewrote the service definition
//     without it — and the documented upgrade path (`install.sh`, the desktop
//     Update button) is a bare `trust-proxy install`.
//
// So the mode now lives here and the service definition carries no mode at all.
// One source of truth, symmetric with the other six.
package modecfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The modes, duplicated from internal/gateway rather than imported: gateway
// imports stores, not the other way round, and a store that imports the engine
// would be an import cycle waiting to happen. gateway.validMode is the authority
// at the point of use; Validate here is the authority at the point of storage.
const (
	ModeManual = "manual"
	ModeSystem = "system"
	ModeTUN    = "tun"
)

// Modes lists the accepted values, in increasing order of interception.
var Modes = []string{ModeManual, ModeSystem, ModeTUN}

type doc struct {
	Mode string `json:"mode"`
}

// Store is a file-backed capture mode.
type Store struct {
	path string
	mu   sync.Mutex
	mode string
}

// NewStore opens the store, seeding manual when the file is absent.
//
// A damaged or unknown value self-heals to manual rather than failing: this file
// is read during startup, so refusing to load it would be a gateway that refuses
// to start, and manual is the value that intercepts least.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path, mode: ModeManual}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	var d doc
	if err := json.Unmarshal(b, &d); err != nil || Validate(d.Mode) != nil {
		s.mode = ModeManual
		_ = s.save()
		return s, nil
	}
	s.mode = d.Mode
	return s, nil
}

// Get returns the stored mode.
func (s *Store) Get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

// Set validates and persists.
func (s *Store) Set(mode string) (string, error) {
	mode = strings.TrimSpace(mode)
	if err := Validate(mode); err != nil {
		return s.Get(), err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
	return s.mode, s.save()
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(doc{Mode: s.mode}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	// 0600, not 0644. Which mode is in force tells a local reader whether traffic
	// is being intercepted, and nothing in the data directory has any reason to be
	// world-readable.
	return os.WriteFile(s.path, b, 0o600)
}

// Validate accepts exactly the three modes.
func Validate(mode string) error {
	for _, m := range Modes {
		if mode == m {
			return nil
		}
	}
	if mode == "" {
		return fmt.Errorf("mode is required (one of %v)", Modes)
	}
	return fmt.Errorf("invalid mode %q (want one of %v)", mode, Modes)
}
