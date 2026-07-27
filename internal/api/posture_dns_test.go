package api

import (
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/dnscfg"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Switching posture must not delete the DNS policy.
//
// applySlot did `if slot.DNS != nil { in.dns = *slot.DNS }` with no else, and
// posture.SeedSplit never sets DNS — so the first switch to Split handed
// ApplyProfile a zero DNSConfig, injectDNS returned early on it, and the config
// came out with no `dns` block at all. Gone with it: the direct-split resolver
// that keeps domestic sites off an overseas edge (the "everything is slow with the
// gateway on" bug), fakeip, hosts, and DoH-via-proxy — in manual mode falling back
// to the system resolver, i.e. resolving in the clear.
//
// Then alignLiveStores called dns.Set with the empty config, dnscfg.validate
// refused it, and the refusal was only logged: the running box had no DNS policy
// while the file still had one, so a restart silently put it back and the evidence
// with it.
//
// The fallback it was missing is next door in resolveProfileDNS, which makes this
// an omission rather than a decision — so both paths now go through one helper.
func TestPostureSwitchKeepsTheDNSPolicyWhenTheSlotHasNone(t *testing.T) {
	dir := t.TempDir()
	store, err := dnscfg.NewStore(filepath.Join(dir, "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	live := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{
			{Tag: "local", Type: "local"},
			{Tag: "doh", Type: "https", Server: "1.1.1.1", Detour: "proxy"},
		},
		Final: "doh",
	}
	if _, err := store.Set(live); err != nil {
		t.Fatal(err)
	}

	s := &Server{dns: store}
	// A seeded Split slot: SeedSplit fills rule sets and policy, never DNS.
	got := s.resolveSlotDNS(apitypes.PolicySlot{})
	if len(got.Servers) != len(live.Servers) || got.Final != live.Final {
		t.Fatalf("a slot with no DNS wiped the live policy: got %+v, want %+v", got, live)
	}
}

// A slot that does carry DNS wins — that is what makes a posture slot a snapshot.
func TestPostureSlotDNSOverridesTheLiveOne(t *testing.T) {
	dir := t.TempDir()
	store, err := dnscfg.NewStore(filepath.Join(dir, "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Set(apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{{Tag: "local", Type: "local"}}, Final: "local",
	}); err != nil {
		t.Fatal(err)
	}

	slotDNS := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{{Tag: "ali", Type: "udp", Server: "223.5.5.5"}},
		Final:   "ali",
	}
	s := &Server{dns: store}
	got := s.resolveSlotDNS(apitypes.PolicySlot{DNS: &slotDNS})
	if got.Final != "ali" || len(got.Servers) != 1 {
		t.Fatalf("the slot's own DNS was not used: got %+v", got)
	}
}

// With no store at all (a stripped-down or probe-only server) the result is empty
// and that is correct — there is no policy to preserve. Asserted so the helper
// cannot start depending on a store being present.
func TestResolveSlotDNSWithoutAStore(t *testing.T) {
	if got := (&Server{}).resolveSlotDNS(apitypes.PolicySlot{}); len(got.Servers) != 0 {
		t.Fatalf("got %+v, want empty", got)
	}
}

// Profiles and postures must answer this the same way. They are the same question
// — "this snapshot did not record DNS, so what runs?" — and having two answers is
// how one of them ended up being "nothing".
func TestProfileAndPostureResolveDNSIdentically(t *testing.T) {
	dir := t.TempDir()
	store, err := dnscfg.NewStore(filepath.Join(dir, "dns.json"))
	if err != nil {
		t.Fatal(err)
	}
	live := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{{Tag: "local", Type: "local"}}, Final: "local",
	}
	if _, err := store.Set(live); err != nil {
		t.Fatal(err)
	}
	s := &Server{dns: store}

	fromProfile := s.resolveProfileDNS(apitypes.Profile{})
	fromSlot := s.resolveSlotDNS(apitypes.PolicySlot{})
	if fromProfile.Final != fromSlot.Final || len(fromProfile.Servers) != len(fromSlot.Servers) {
		t.Fatalf("profile resolves to %+v, posture to %+v", fromProfile, fromSlot)
	}
}
