// Package inboundcfg persists where the mixed proxy inbound listens.
//
// It exists for the same reason internal/modecfg does: this was a setting with
// no store. The listen address and port lived in configs/config.json — the file
// that is seeded on first boot and that the docs explicitly tell you not to
// hand-edit — and nowhere else. So the one knob every client on the machine is
// pointed at was reachable from no layer: not the API, not the CLI, not the
// console. "Listen on the LAN so my phone can use this gateway" had no answer
// short of editing a file behind the gateway's back.
//
// Zero values mean "whatever the base config says", so an existing machine that
// has never written this file behaves byte-for-byte as before.
package inboundcfg

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Ports the gateway already listens on for its own control surfaces. Binding
// the proxy to one of them does not merely conflict — it produces a gateway
// whose console or Clash API is silently shadowed, so it is refused at the
// store rather than discovered at rebuild time.
const (
	apiPort   = 21585
	clashPort = 21586
)

// Store is a file-backed inbound listen point, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data apitypes.InboundListen
}

// NewStore opens (or seeds) the store at path.
//
// A damaged or invalid file self-heals to the zero value rather than failing:
// this is read during startup, and refusing to load it would be a gateway that
// will not start over a setting whose absence simply means "use the default".
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	var d apitypes.InboundListen
	if err := json.Unmarshal(b, &d); err != nil || Validate(d) != nil {
		s.data = apitypes.InboundListen{}
		_ = s.save()
		return s, nil
	}
	s.data = d
	return s, nil
}

// Get returns the stored value, zero fields and all.
func (s *Store) Get() apitypes.InboundListen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// Resolved returns the stored value with defaults filled in — what the data
// plane will actually bind.
func (s *Store) Resolved() apitypes.InboundListen { return s.Get().Resolved() }

// Set validates and persists.
func (s *Store) Set(l apitypes.InboundListen) (apitypes.InboundListen, error) {
	if err := Validate(l); err != nil {
		return s.Get(), err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = l
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
	// 0600 like the rest of the data directory: which address the proxy answers
	// on is not something an unprivileged local reader needs.
	return os.WriteFile(s.path, b, 0o600)
}

// Validate accepts the zero value (meaning "default") and any well-formed
// address/port that does not collide with our own control ports.
func Validate(l apitypes.InboundListen) error {
	if l.Listen != "" {
		if net.ParseIP(l.Listen) == nil {
			return fmt.Errorf("invalid listen address %q (want an IP such as 127.0.0.1 or 0.0.0.0)", l.Listen)
		}
	}
	if l.Port != 0 {
		if l.Port < 1 || l.Port > 65535 {
			return fmt.Errorf("port must be between 1 and 65535, got %d", l.Port)
		}
		switch l.Port {
		case apiPort:
			return fmt.Errorf("port %d is the console/API port; the proxy cannot share it", l.Port)
		case clashPort:
			return fmt.Errorf("port %d is the Clash API port; the proxy cannot share it", l.Port)
		}
	}
	return nil
}

// IsLoopback reports whether the resolved listen address only accepts
// connections from this machine. Callers use it to decide whether opening the
// proxy needs credentials first — the API layer owns that rule, because it is
// the only layer that can see the user registry.
func IsLoopback(l apitypes.InboundListen) bool {
	ip := net.ParseIP(l.Resolved().Listen)
	return ip != nil && ip.IsLoopback()
}
