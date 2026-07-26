package detect

import "github.com/ivanzzeth/trust-proxy/pkg/apitypes"

// The engine's own copy of the shipped thresholds. internal/detectcfg owns the
// persisted document and the same numbers; duplicating them here (rather than
// importing that package) keeps detect free of a dependency on the config store,
// which imports apitypes only. withEngineDefaults is what makes a partially
// filled config — an older file, or a hand-written PUT — safe to apply.
type tunables struct {
	beaconReAlertFactor int
	dgaMinLabelLen      int
	dgaMinEntropy       float64
	tunnelMinLabelLen   int
	tunnelMinEntropy    float64
	subdomainAlertAt    int
	exfilMinRatio       float64
	exfilNewDestHours   int
	queryWindowSec      int
	queryNXBurst        int
	queryParentRate     int
	queryOddTypeAt      int
}

func defaultTunables() tunables {
	return tunables{
		beaconReAlertFactor: 36,
		dgaMinLabelLen:      12,
		dgaMinEntropy:       3.8,
		tunnelMinLabelLen:   25,
		tunnelMinEntropy:    4.0,
		subdomainAlertAt:    40,
		exfilMinRatio:       4,
		exfilNewDestHours:   24,
		queryWindowSec:      300,
		queryNXBurst:        30,
		queryParentRate:     300,
		queryOddTypeAt:      20,
	}
}

// withEngineDefaults fills zero thresholds so a sparse config can't disable a
// detector by omission. Ratio / new-destination windows are left at zero when
// asked for: there, 0 explicitly means "ignore this signal".
func withEngineDefaults(c apitypes.DetectionConfig) apitypes.DetectionConfig {
	d := defaultTunables()
	if c.BeaconMinSample <= 0 {
		c.BeaconMinSample = 6
	}
	if c.BeaconCV <= 0 {
		c.BeaconCV = 0.25
	}
	if c.BeaconMinInterval <= 0 {
		c.BeaconMinInterval = 5
	}
	if c.BeaconMaxInterval <= 0 {
		c.BeaconMaxInterval = 7200
	}
	if c.BeaconReAlert <= 0 {
		c.BeaconReAlert = 600
	}
	if c.BeaconReAlertFactor <= 0 {
		c.BeaconReAlertFactor = d.beaconReAlertFactor
	}
	if c.DGAMinLabelLen <= 0 {
		c.DGAMinLabelLen = d.dgaMinLabelLen
	}
	if c.DGAMinEntropy <= 0 {
		c.DGAMinEntropy = d.dgaMinEntropy
	}
	if c.TunnelMinLabelLen <= 0 {
		c.TunnelMinLabelLen = d.tunnelMinLabelLen
	}
	if c.TunnelMinEntropy <= 0 {
		c.TunnelMinEntropy = d.tunnelMinEntropy
	}
	if c.SubdomainAlertAt <= 0 {
		c.SubdomainAlertAt = d.subdomainAlertAt
	}
	if c.ExfilUploadBytes <= 0 {
		c.ExfilUploadBytes = 10 << 20
	}
	if c.QueryWindowSec <= 0 {
		c.QueryWindowSec = d.queryWindowSec
	}
	// The three query thresholds keep 0 as "ignore this signal".
	return c
}
