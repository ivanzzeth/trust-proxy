// Package retentioncfg persists how much of the gateway's own output stays on
// disk: the daemon log and the per-connection history, both rotated by
// lumberjack.
//
// Eight `serve` flags used to be the only way to set these, which made them
// unsettable in practice: the gateway runs as a system service, so the flags
// live in the launchd plist / systemd unit, and the documented upgrade path is
// a bare `trust-proxy install` that rewrites that definition without them. Same
// failure mode as the capture mode before internal/modecfg, and the same fix —
// a store the service definition knows nothing about.
package retentioncfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// NoRotation is the MaxSizeMB value that turns rotation off, mirroring
// `--log-max-size 0`. It cannot be spelled 0 here because 0 already means
// "unset, use the default" for every other field in the struct.
const NoRotation = -1

// Store is a file-backed retention policy, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data apitypes.Retention
}

// NewStore opens (or seeds) the store at path. An unreadable or invalid file
// self-heals to the zero value (= all defaults) rather than failing: this is
// read at startup, and no retention setting is worth refusing to boot over.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	var d apitypes.Retention
	if err := json.Unmarshal(b, &d); err != nil || Validate(d) != nil {
		s.data = apitypes.Retention{}
		_ = s.save()
		return s, nil
	}
	s.data = d
	return s, nil
}

// Get returns a snapshot, zero fields and all.
func (s *Store) Get() apitypes.Retention {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// Set validates and persists.
func (s *Store) Set(r apitypes.Retention) (apitypes.Retention, error) {
	if err := Validate(r); err != nil {
		return s.Get(), err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = r
	return s.data, s.save()
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

// Validate rejects values that would be read as a working setting and behave as
// something else.
func Validate(r apitypes.Retention) error {
	if err := validateRule("log", r.Log); err != nil {
		return err
	}
	return validateRule("history", r.History)
}

func validateRule(name string, r apitypes.RetentionRule) error {
	if r.MaxSizeMB < NoRotation {
		return fmt.Errorf("%s.max_size_mb must be >= %d (%d disables rotation, 0 uses the default)", name, NoRotation, NoRotation)
	}
	if r.MaxBackups < 0 {
		return fmt.Errorf("%s.max_backups cannot be negative", name)
	}
	if r.MaxAgeDays < 0 {
		return fmt.Errorf("%s.max_age_days cannot be negative", name)
	}
	// History rotation is not optional: the store replays the live file at
	// startup to rebuild its aggregates, so an unbounded history file turns
	// every boot into a full re-read of everything the gateway has ever seen.
	if name == "history" && r.MaxSizeMB == NoRotation {
		return fmt.Errorf("history rotation cannot be disabled: startup replays the live file, so an unbounded one makes boot time grow without limit")
	}
	return nil
}
