package dnscfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// The default must bootstrap without exits AND keep a proxied resolver ready.
//
// Final used to be DoH→proxy (1.1.1.1). With zero applied nodes proxy is
// selector[direct], so that DoH is a direct Cloudflare dial — commonly dead in
// CN, hanging every hijack-dns lookup and blocking subscription fetch. Final is
// therefore a domestic UDP resolver; DoH-via-proxy stays as a declared server
// so injectDirectDNS / operators can use it once exits exist.
func TestDefaultBootstrapsWithoutExits(t *testing.T) {
	d := Defaults()

	byTag := map[string]apitypes.DNSServer{}
	for _, s := range d.Servers {
		byTag[s.Tag] = s
	}
	if d.Final == "" {
		t.Fatal("no final resolver")
	}
	fin, ok := byTag[d.Final]
	if !ok {
		t.Fatalf("final %q is not a declared server", d.Final)
	}
	if fin.Detour == "proxy" {
		t.Fatalf("final resolver %q has detour=proxy — CN bootstrap with no exits blackholes DNS", d.Final)
	}
	var hasProxied bool
	for _, s := range d.Servers {
		if s.Detour == "proxy" {
			hasProxied = true
			break
		}
	}
	if !hasProxied {
		t.Fatal("defaults must still declare a detour=proxy resolver for once exits exist")
	}
	for _, r := range d.Rules {
		if len(r.RuleSet) > 0 {
			t.Fatalf("the default names rule set %v, which a fresh install does not have", r.RuleSet)
		}
	}
	if err := validate(d); err != nil {
		t.Fatalf("the default config does not validate: %v", err)
	}
}

// An install already running the abandoned default has to heal on upgrade.
//
// Changing Defaults() only helps a machine with no dns.json yet, and the
// machines that need it most already have one saying "resolve everything with
// the system resolver". Without this they would query every proxied domain in the
// clear forever, and nothing would ever tell them.
func TestUpgradeHealsTheAbandonedDefaultAndNothingElse(t *testing.T) {
	write := func(t *testing.T, c apitypes.DNSConfig) *Store {
		t.Helper()
		path := filepath.Join(t.TempDir(), "dns.json")
		b, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		s, err := NewStore(path)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// The untouched old default: replaced.
	s := write(t, abandonedDefault())
	if got := s.Get(); got.Final == "local" {
		t.Fatal("an untouched old default survived the upgrade — every proxied domain would still leak")
	}

	// A deliberate choice of the system resolver: respected. LAN-only and
	// air-gapped deployments want exactly this, and overriding it would break them
	// to fix somebody else's problem.
	chosen := abandonedDefault()
	chosen.Strategy = "prefer_ipv4" // any edit at all proves a human was here
	s = write(t, chosen)
	if got := s.Get(); got.Final != "local" {
		t.Fatal("a configured system-resolver setup was overwritten")
	}

	// So is anything already resolving through the proxy.
	mine := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{{Tag: "mine", Type: "https", Server: "9.9.9.9", Detour: "proxy"}},
		Rules:   []apitypes.DNSRule{},
		Final:   "mine",
	}
	s = write(t, mine)
	if got := s.Get(); got.Final != "mine" {
		t.Fatalf("somebody's own resolver was replaced: %+v", got)
	}
}
