package dnscfg

import "testing"

// The default must not be a resolver that leaks.
//
// It was `local` alone, which is the one shape this package's own doc comment
// argues against: every domain you then proxy is still queried in the clear
// against whatever the OS points at, a censored domain answers with a poisoned
// address, and injectDirectDNS — the whole "DNS follows route" mechanism — never
// activates, because it only splits away from a resolver that sits behind the
// proxy. Every fresh install ran that way and nothing said so.
func TestDefaultResolvesThroughTheExit(t *testing.T) {
	d := defaultConfig()

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
