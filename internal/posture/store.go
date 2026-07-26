// Package posture persists the global Strict|Split dual-slot policy state.
// Live stores (whitelist.json etc.) remain the working copy for the active
// posture; slots hold the inactive side so switching does not cross-contaminate.
package posture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// State is the on-disk posture file.
type State struct {
	Active string                         `json:"active"`
	Slots  map[string]apitypes.PolicySlot `json:"slots"`
}

// Store is a file-backed posture state.
type Store struct {
	path string
	mu   sync.Mutex
	data State
}

// NewStore opens (or seeds) posture.json. Missing file → active=strict, empty slots.
func NewStore(path string) (*Store, error) {
	s := &Store{
		path: path,
		data: State{
			Active: apitypes.PostureStrict,
			Slots: map[string]apitypes.PolicySlot{
				apitypes.PostureStrict: {},
				apitypes.PostureSplit:  {},
			},
		},
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	if !apitypes.ValidPosture(s.data.Active) {
		s.data.Active = apitypes.PostureStrict
	}
	if s.data.Slots == nil {
		s.data.Slots = map[string]apitypes.PolicySlot{}
	}
	for _, name := range []string{apitypes.PostureStrict, apitypes.PostureSplit} {
		if _, ok := s.data.Slots[name]; !ok {
			s.data.Slots[name] = apitypes.PolicySlot{}
		}
	}
	return s, s.save()
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

// Get returns a deep-ish copy of the state.
func (s *Store) Get() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.data)
}

// Active returns the current posture name.
func (s *Store) Active() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Active
}

// Slot returns a copy of one slot.
func (s *Store) Slot(name string) (apitypes.PolicySlot, error) {
	if !apitypes.ValidPosture(name) {
		return apitypes.PolicySlot{}, fmt.Errorf("invalid posture %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSlot(s.data.Slots[name]), nil
}

// PutSlot replaces one slot and persists.
func (s *Store) PutSlot(name string, slot apitypes.PolicySlot) error {
	if !apitypes.ValidPosture(name) {
		return fmt.Errorf("invalid posture %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Slots[name] = cloneSlot(slot)
	return s.save()
}

// SetActive sets the active posture name and persists.
func (s *Store) SetActive(name string) error {
	if !apitypes.ValidPosture(name) {
		return fmt.Errorf("invalid posture %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Active = name
	return s.save()
}

// SaveState replaces the whole state (used after switch commit).
func (s *Store) SaveState(st State) error {
	if !apitypes.ValidPosture(st.Active) {
		return fmt.Errorf("invalid posture %q", st.Active)
	}
	if st.Slots == nil {
		st.Slots = map[string]apitypes.PolicySlot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = cloneState(st)
	return s.save()
}

func cloneState(st State) State {
	out := State{Active: st.Active, Slots: make(map[string]apitypes.PolicySlot, len(st.Slots))}
	for k, v := range st.Slots {
		out.Slots[k] = cloneSlot(v)
	}
	return out
}

func cloneSlot(s apitypes.PolicySlot) apitypes.PolicySlot {
	out := apitypes.PolicySlot{
		Whitelist: apitypes.Rules{
			Domains:   append([]string(nil), s.Whitelist.Domains...),
			IPs:       append([]string(nil), s.Whitelist.IPs...),
			Processes: append([]string(nil), s.Whitelist.Processes...),
			Devices:   append([]string(nil), s.Whitelist.Devices...),
		},
		Blacklist: apitypes.Blacklist{
			Domains:  append([]string(nil), s.Blacklist.Domains...),
			Keywords: append([]string(nil), s.Blacklist.Keywords...),
			Regexes:  append([]string(nil), s.Blacklist.Regexes...),
			IPs:      append([]string(nil), s.Blacklist.IPs...),
		},
		Directlist: apitypes.DirectList{
			Domains: append([]string(nil), s.Directlist.Domains...),
			IPs:     append([]string(nil), s.Directlist.IPs...),
		},
		CustomRules: append([]apitypes.CustomRule(nil), s.CustomRules...),
		RuleSets:    append([]apitypes.RuleSet(nil), s.RuleSets...),
		Final:       s.Final,
		Seeded:      s.Seeded,
	}
	if s.ProxyGroups != nil {
		pg := *s.ProxyGroups
		pg.ExcludeCountries = append([]string(nil), s.ProxyGroups.ExcludeCountries...)
		pg.Groups = append([]apitypes.ProxyGroup(nil), s.ProxyGroups.Groups...)
		out.ProxyGroups = &pg
	}
	if s.DNS != nil {
		d := *s.DNS
		out.DNS = &d
	}
	return out
}
