// Package detectcfg persists the detection engine's tunables (data/detection.json).
// They were constants: changing how sensitive beaconing is, or what counts as an
// exfil-shaped upload, meant a rebuild — so in practice nobody tuned them and the
// alert stream was whatever the defaults happened to produce.
package detectcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Defaults are the shipped thresholds. They are also the fallback for any zero
// field, so a config written by an older build keeps working.
func Defaults() apitypes.DetectionConfig {
	return apitypes.DetectionConfig{
		BeaconEnabled:       true,
		BeaconMinSample:     6,
		BeaconCV:            0.25,
		BeaconMinInterval:   5,
		BeaconMaxInterval:   7200,
		BeaconReAlert:       600,
		BeaconReAlertFactor: 36,

		DGAEnabled:        true,
		DGAMinLabelLen:    12,
		DGAMinEntropy:     3.8,
		TunnelMinLabelLen: 25,
		TunnelMinEntropy:  4.0,
		SubdomainAlertAt:  40,

		ExfilUploadBytes:  10 << 20,
		ExfilMinRatio:     4,
		ExfilNewDestHours: 24,

		QueryWindowSec:  300,
		QueryNXBurst:    30,
		QueryParentRate: 300,
		QueryOddTypeAt:  20,

		AutoBlock:         true,
		RequireWarmPermit: true,
	}
}

// WithDefaults fills every zero threshold from Defaults. Booleans are taken as
// written (they are meaningful when false), so callers hand us a complete
// document — the store guarantees that by round-tripping through Set.
func WithDefaults(c apitypes.DetectionConfig) apitypes.DetectionConfig {
	d := Defaults()
	if c.BeaconMinSample <= 0 {
		c.BeaconMinSample = d.BeaconMinSample
	}
	if c.BeaconCV <= 0 {
		c.BeaconCV = d.BeaconCV
	}
	if c.BeaconMinInterval <= 0 {
		c.BeaconMinInterval = d.BeaconMinInterval
	}
	if c.BeaconMaxInterval <= 0 {
		c.BeaconMaxInterval = d.BeaconMaxInterval
	}
	if c.BeaconReAlert <= 0 {
		c.BeaconReAlert = d.BeaconReAlert
	}
	if c.BeaconReAlertFactor <= 0 {
		c.BeaconReAlertFactor = d.BeaconReAlertFactor
	}
	if c.DGAMinLabelLen <= 0 {
		c.DGAMinLabelLen = d.DGAMinLabelLen
	}
	if c.DGAMinEntropy <= 0 {
		c.DGAMinEntropy = d.DGAMinEntropy
	}
	if c.TunnelMinLabelLen <= 0 {
		c.TunnelMinLabelLen = d.TunnelMinLabelLen
	}
	if c.TunnelMinEntropy <= 0 {
		c.TunnelMinEntropy = d.TunnelMinEntropy
	}
	if c.SubdomainAlertAt <= 0 {
		c.SubdomainAlertAt = d.SubdomainAlertAt
	}
	if c.ExfilUploadBytes <= 0 {
		c.ExfilUploadBytes = d.ExfilUploadBytes
	}
	if c.QueryWindowSec <= 0 {
		c.QueryWindowSec = d.QueryWindowSec
	}
	// ExfilMinRatio / ExfilNewDestHours are deliberately not defaulted from zero:
	// 0 means "ignore this signal", which is a legitimate choice.
	return c
}

// Validate rejects settings that would silently disable detection or produce
// nonsense (an inverted interval window can never match).
func Validate(c apitypes.DetectionConfig) error {
	if c.BeaconMinSample < 3 {
		return fmt.Errorf("beacon_min_sample must be >= 3 (need at least two intervals to judge a cadence)")
	}
	if c.BeaconCV <= 0 || c.BeaconCV > 2 {
		return fmt.Errorf("beacon_cv must be in (0, 2]")
	}
	if c.BeaconMinInterval <= 0 || c.BeaconMaxInterval <= c.BeaconMinInterval {
		return fmt.Errorf("beacon interval window must satisfy 0 < min < max")
	}
	if c.BeaconReAlert < 0 || c.BeaconReAlertFactor < 1 {
		return fmt.Errorf("beacon_realert_s must be >= 0 and beacon_realert_factor >= 1")
	}
	if c.DGAMinLabelLen < 4 || c.TunnelMinLabelLen < 4 {
		return fmt.Errorf("label length thresholds must be >= 4")
	}
	if c.DGAMinEntropy <= 0 || c.TunnelMinEntropy <= 0 {
		return fmt.Errorf("entropy thresholds must be > 0")
	}
	if c.SubdomainAlertAt < 2 {
		return fmt.Errorf("subdomain_alert_at must be >= 2")
	}
	if c.ExfilUploadBytes < 1<<20 {
		return fmt.Errorf("exfil_upload_bytes must be >= 1 MiB (anything smaller alerts on ordinary traffic)")
	}
	if c.ExfilMinRatio < 0 || c.ExfilNewDestHours < 0 {
		return fmt.Errorf("exfil_min_ratio and exfil_new_dest_hours must be >= 0")
	}
	if c.QueryWindowSec < 10 {
		return fmt.Errorf("query_window_s must be >= 10 (a shorter window can't establish a rate)")
	}
	if c.QueryNXBurst < 0 || c.QueryParentRate < 0 || c.QueryOddTypeAt < 0 {
		return fmt.Errorf("query thresholds must be >= 0 (0 disables that signal)")
	}
	return nil
}

// Store is a file-backed detection config, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data apitypes.DetectionConfig
}

// NewStore loads (creating with defaults) the config at path.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.data = Defaults()
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	s.data = WithDefaults(s.data)
	return s, nil
}

// Get returns the effective config.
func (s *Store) Get() apitypes.DetectionConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// Set validates and replaces the config.
func (s *Store) Set(c apitypes.DetectionConfig) (apitypes.DetectionConfig, error) {
	c = WithDefaults(c)
	if err := Validate(c); err != nil {
		return s.Get(), err
	}
	s.mu.Lock()
	s.data = c
	err := s.save()
	s.mu.Unlock()
	return s.Get(), err
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
