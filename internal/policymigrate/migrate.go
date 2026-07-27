// Package policymigrate performs one-shot Permit⊥Route migrations on data dir
// stores: legacy rule-set roles, and copying directlist matchers into the
// whitelist so "no-proxy used to imply allow" keeps working after Route no
// longer opens the gate.
package policymigrate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

const markerName = "policy-v2.migrated"

// Run applies idempotent migrations under dataDir. Safe to call on every serve.
func Run(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	marker := filepath.Join(dataDir, markerName)
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	if err := migrateDirectlistToWhitelist(dataDir); err != nil {
		return err
	}
	if err := migrateProfilesVersion(dataDir); err != nil {
		return err
	}
	return os.WriteFile(marker, []byte("ok\n"), 0o600)
}

// migrateDirectlistToWhitelist copies no-proxy domains/IPs into whitelist so
// previously-working "bypass = allow" setups stay permitted after Route stops
// granting L3. Rule-set role rewrite happens in ruleset.NewStore.
func migrateDirectlistToWhitelist(dataDir string) error {
	dlPath := filepath.Join(dataDir, "directlist.json")
	wlPath := filepath.Join(dataDir, "whitelist.json")
	dlB, err := os.ReadFile(dlPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var dl struct {
		Domains []string `json:"domains"`
		IPs     []string `json:"ips"`
	}
	if err := json.Unmarshal(dlB, &dl); err != nil {
		return fmt.Errorf("directlist: %w", err)
	}
	if len(dl.Domains) == 0 && len(dl.IPs) == 0 {
		return nil
	}
	var wl apitypes.Rules
	if b, err := os.ReadFile(wlPath); err == nil {
		_ = json.Unmarshal(b, &wl)
	}
	if wl.Domains == nil {
		wl.Domains = []string{}
	}
	if wl.IPs == nil {
		wl.IPs = []string{}
	}
	seenD := map[string]bool{}
	for _, d := range wl.Domains {
		seenD[d] = true
	}
	seenIP := map[string]bool{}
	for _, ip := range wl.IPs {
		seenIP[ip] = true
	}
	changed := false
	for _, d := range dl.Domains {
		if d != "" && !seenD[d] {
			wl.Domains = append(wl.Domains, d)
			seenD[d] = true
			changed = true
		}
	}
	for _, ip := range dl.IPs {
		if ip != "" && !seenIP[ip] {
			wl.IPs = append(wl.IPs, ip)
			seenIP[ip] = true
			changed = true
		}
	}
	if !changed {
		return nil
	}
	out, err := json.MarshalIndent(wl, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(wlPath, out, 0o600)
}

func migrateProfilesVersion(dataDir string) error {
	path := filepath.Join(dataDir, "profiles.json")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var profiles []apitypes.Profile
	if err := json.Unmarshal(b, &profiles); err != nil {
		return nil // don't fail serve on unexpected shape
	}
	changed := false
	for i := range profiles {
		if profiles[i].Version < apitypes.ProfilePolicyVersion {
			for j := range profiles[i].RuleSets {
				old := profiles[i].RuleSets[j].Role
				neu := apitypes.NormalizeRuleRole(old)
				if neu != old {
					profiles[i].RuleSets[j].Role = neu
					changed = true
				}
			}
			profiles[i].Version = apitypes.ProfilePolicyVersion
			changed = true
		}
	}
	if !changed {
		return nil
	}
	out, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}
