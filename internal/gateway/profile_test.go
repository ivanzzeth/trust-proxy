package gateway

import (
	"testing"

	"github.com/sagernet/sing-box/log"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// ApplyProfile must assign the full policy surface on the manager before rebuild.
// We assert by forcing rebuild to fail (bad config path) and checking that the
// reverted state matches the previous live policy — proving both the swap-in
// and the rollback paths touch bl/dl/cr/pg/dns, not only wl/sets/mode.
func TestApplyProfile_FullPolicyRollback(t *testing.T) {
	m := &Manager{
		configPath: "/nonexistent/no-such-config.json",
		logger:     log.StdLogger(),
		mode:       ModeManual,
		wl:         whitelist.Rules{Domains: []string{"old.com"}},
		bl:         blacklist.Rules{Domains: []string{"evil-old.com"}},
		dl:         directlist.Rules{Domains: []string{"lan-old.local"}},
		cr: customrules.Rules{Rules: []apitypes.CustomRule{
			{Match: "domain_suffix", Value: "old-pack.com", Action: "proxy", Pack: "Old", Enabled: true},
		}},
		pg:    proxygroups.Config{AutoCountry: false},
		dns:   apitypes.DNSConfig{Final: "local", Servers: []apitypes.DNSServer{{Tag: "local", Type: "local"}}},
		final: "proxy",
	}

	err := m.ApplyProfile(
		nil,
		whitelist.Rules{Domains: []string{"new.com"}},
		blacklist.Rules{Domains: []string{"evil-new.com"}},
		directlist.Rules{Domains: []string{"corp.local"}},
		customrules.Rules{Rules: []apitypes.CustomRule{
			{Match: "domain_suffix", Value: "github.com", Action: "proxy", Pack: "Dev", Enabled: true},
		}},
		ruleset.Sets{Sets: []apitypes.RuleSet{{Tag: "geosite-github", Enabled: true}}},
		proxygroups.Config{AutoCountry: true, ExcludeCountries: []string{"HK"}},
		apitypes.DNSConfig{Final: "doh", Servers: []apitypes.DNSServer{{Tag: "doh", Type: "https"}}},
		ModeSystem,
		"direct",
	)
	if err == nil {
		t.Fatal("expected ApplyProfile to fail on missing config")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.wl.Domains) != 1 || m.wl.Domains[0] != "old.com" {
		t.Fatalf("wl should revert to old.com, got %+v", m.wl)
	}
	if len(m.bl.Domains) != 1 || m.bl.Domains[0] != "evil-old.com" {
		t.Fatalf("bl should revert, got %+v", m.bl)
	}
	if len(m.dl.Domains) != 1 || m.dl.Domains[0] != "lan-old.local" {
		t.Fatalf("dl should revert, got %+v", m.dl)
	}
	if len(m.cr.Rules) != 1 || m.cr.Rules[0].Value != "old-pack.com" {
		t.Fatalf("cr should revert, got %+v", m.cr)
	}
	if m.pg.AutoCountry {
		t.Fatalf("pg should revert AutoCountry=false, got %+v", m.pg)
	}
	if m.dns.Final != "local" {
		t.Fatalf("dns should revert Final=local, got %+v", m.dns)
	}
	if m.mode != ModeManual {
		t.Fatalf("mode should revert to manual, got %q", m.mode)
	}
	if m.final != "proxy" {
		t.Fatalf("final should revert to proxy, got %q", m.final)
	}
}
