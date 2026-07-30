package dnscfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// The default must not be a resolver that leaks.
//
// It was `local` alone, which is the one shape this package's own doc comment
// argues against: every domain you then proxy is still queried in the clear
// against whatever the OS points at, a censored domain answers with a poisoned
// address, and injectDirectDNS — the whole "DNS follows route" mechanism — never
// activates, because it only splits away from a resolver that sits behind the
// proxy. Every fresh install ran that way and nothing said so.
func TestDefaultResolvesThroughTheExit(t *testing.T) {
	d := Defaults()

	byTag := map[string]string{}
	for _, s := range d.Servers {
		byTag[s.Tag] = s.Detour
	}
	if d.Final == "" {
		t.Fatal("no final resolver")
	}
	if byTag[d.Final] != "proxy" {
		t.Fatalf("final resolver %q has detour %q — a fresh install would query every domain in the clear",
			d.Final, byTag[d.Final])
	}
	// A rule naming a rule set would dangle on a fresh install (there are none to
	// name), and the box refuses to start on a dangling reference. injectDirectDNS
	// mirrors the real route table instead, so none is needed here.
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
