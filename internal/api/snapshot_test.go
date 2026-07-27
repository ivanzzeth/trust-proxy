package api

import (
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/dnscfg"
	"github.com/ivanzzeth/trust-proxy/internal/finalroute"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// newLivePolicyServer builds a Server backed by real (tmp-dir) stores, seeded
// with distinguishable data on every policy axis snapshotLiveSlot/
// snapshotProfile capture — used to pin down that both agree on the shared
// fields before/after refactoring their common logic into one helper.
func newLivePolicyServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	wl, err := whitelist.NewStore(dir + "/whitelist.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wl.AddDomain("allowed.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := wl.AddProcess("curl"); err != nil {
		t.Fatal(err)
	}

	bl, err := blacklist.NewStore(dir + "/blacklist.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bl.AddKeyword("ads"); err != nil {
		t.Fatal(err)
	}

	dl, err := directlist.NewStore(dir + "/directlist.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dl.AddDomain("intra.corp.example"); err != nil {
		t.Fatal(err)
	}

	cr, err := customrules.NewStore(dir + "/customrules.json")
	if err != nil {
		t.Fatal(err)
	}
	permit := true
	if _, err := cr.Add(apitypes.CustomRule{
		Match: apitypes.CustomMatchDomainSuffix, Value: "pack.example",
		Egress: apitypes.CustomEgressProxy, Permit: &permit, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	rs, err := ruleset.NewStore(dir + "/rulesets.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Add(apitypes.RuleSet{
		Tag: "geosite-slack", Name: "Slack", Type: "remote", Format: "binary",
		URL: "https://example.com/slack.srs", Role: apitypes.RuleRolePermit, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	pg, err := proxygroups.NewStore(dir + "/proxygroups.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Set(proxygroups.Config{AutoCountry: true, ExcludeCountries: []string{"CN"}}); err != nil {
		t.Fatal(err)
	}

	dns, err := dnscfg.NewStore(dir + "/dns.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dns.Set(apitypes.DNSConfig{
		Servers:  []apitypes.DNSServer{{Tag: "local", Type: "udp", Server: "1.1.1.1"}},
		Strategy: "ipv4_only",
	}); err != nil {
		t.Fatal(err)
	}

	final, err := finalroute.NewStore(dir + "/final.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := final.Set(finalroute.Config{Outbound: "direct"}); err != nil {
		t.Fatal(err)
	}

	return &Server{wl: wl, bl: bl, dl: dl, cr: cr, rs: rs, pgroups: pg, dns: dns, final: final}
}

func TestSnapshotLiveSlotAndSnapshotProfileAgree(t *testing.T) {
	s := newLivePolicyServer(t)

	slot := s.snapshotLiveSlot()
	p := s.snapshotProfile("my-profile")

	if slot.Whitelist.Domains[0] != "allowed.example" || p.Whitelist.Domains[0] != "allowed.example" {
		t.Fatalf("whitelist domains: slot=%v profile=%v", slot.Whitelist, p.Whitelist)
	}
	if len(slot.Whitelist.Processes) != 1 || slot.Whitelist.Processes[0] != p.Whitelist.Processes[0] {
		t.Fatalf("whitelist processes mismatch: slot=%v profile=%v", slot.Whitelist, p.Whitelist)
	}
	if len(slot.Blacklist.Keywords) != 1 || slot.Blacklist.Keywords[0] != p.Blacklist.Keywords[0] {
		t.Fatalf("blacklist mismatch: slot=%v profile=%v", slot.Blacklist, p.Blacklist)
	}
	if len(slot.Directlist.Domains) != 1 || slot.Directlist.Domains[0] != p.Directlist.Domains[0] {
		t.Fatalf("directlist mismatch: slot=%v profile=%v", slot.Directlist, p.Directlist)
	}
	if len(slot.CustomRules) != 1 || len(p.CustomRules) != 1 || slot.CustomRules[0].Value != p.CustomRules[0].Value {
		t.Fatalf("custom rules mismatch: slot=%v profile=%v", slot.CustomRules, p.CustomRules)
	}
	if len(slot.RuleSets) != 1 || len(p.RuleSets) != 1 || slot.RuleSets[0].Tag != p.RuleSets[0].Tag {
		t.Fatalf("rule sets mismatch: slot=%v profile=%v", slot.RuleSets, p.RuleSets)
	}
	if slot.ProxyGroups == nil || p.ProxyGroups == nil || slot.ProxyGroups.AutoCountry != p.ProxyGroups.AutoCountry ||
		len(slot.ProxyGroups.ExcludeCountries) != 1 || slot.ProxyGroups.ExcludeCountries[0] != p.ProxyGroups.ExcludeCountries[0] {
		t.Fatalf("proxy groups mismatch: slot=%v profile=%v", slot.ProxyGroups, p.ProxyGroups)
	}
	if slot.DNS == nil || p.DNS == nil || slot.DNS.Strategy != "ipv4_only" || p.DNS.Strategy != "ipv4_only" {
		t.Fatalf("dns mismatch: slot=%v profile=%v", slot.DNS, p.DNS)
	}
	if slot.Final != "direct" || p.Final != "direct" {
		t.Fatalf("final mismatch: slot=%q profile=%q", slot.Final, p.Final)
	}
	// Profile carries the legacy enabled-tags projection too.
	if len(p.RuleSetTags) != 1 || p.RuleSetTags[0] != "geosite-slack" {
		t.Fatalf("expected legacy RuleSetTags populated, got %v", p.RuleSetTags)
	}
}

// fakeProfileApplier records the ApplyProfile call and lets the test drive
// success/failure without a real gateway.Manager.
type fakeProfileApplier struct {
	err         error
	lastWL      whitelist.Rules
	lastBL      blacklist.Rules
	lastDL      directlist.Rules
	lastCR      customrules.Rules
	lastSets    ruleset.Sets
	lastPG      proxygroups.Config
	lastDNS     apitypes.DNSConfig
	lastFinal   string
	lastMode    string
	lastPosture string
}

func (f *fakeProfileApplier) ApplyProfile(nodes []apitypes.Node, wl whitelist.Rules, bl blacklist.Rules, dl directlist.Rules, cr customrules.Rules, sets ruleset.Sets, pg proxygroups.Config, dns apitypes.DNSConfig, mode, final, posture string) error {
	f.lastWL, f.lastBL, f.lastDL, f.lastCR, f.lastSets, f.lastPG, f.lastDNS, f.lastMode, f.lastFinal, f.lastPosture =
		wl, bl, dl, cr, sets, pg, dns, mode, final, posture
	return f.err
}
func (f *fakeProfileApplier) Nodes() []apitypes.Node  { return nil }
func (f *fakeProfileApplier) Posture() string         { return apitypes.PostureStrict }
func (f *fakeProfileApplier) SetPosture(string) error { return nil }

func TestApplySlotAlignsLiveStoresOnSuccess(t *testing.T) {
	s := newLivePolicyServer(t)
	fa := &fakeProfileApplier{}
	s.profApplier = fa

	// A slot with DIFFERENT content than the current live stores, to prove
	// applySlot's alignment actually overwrites (not a no-op check).
	slot := apitypes.PolicySlot{
		Whitelist: apitypes.Rules{Domains: []string{"other.example"}},
		Final:     "proxy",
	}
	if _, err := s.applySlot(slot, apitypes.PostureSplit); err != nil {
		t.Fatal(err)
	}
	if fa.lastPosture != apitypes.PostureSplit {
		t.Fatalf("expected posture passed through, got %q", fa.lastPosture)
	}
	if got := s.wl.Get(); len(got.Domains) != 1 || got.Domains[0] != "other.example" {
		t.Fatalf("whitelist store not aligned after applySlot: %+v", got)
	}
}

func TestApplySlotDoesNotAlignStoresOnFailure(t *testing.T) {
	s := newLivePolicyServer(t)
	fa := &fakeProfileApplier{err: errFake}
	s.profApplier = fa

	slot := apitypes.PolicySlot{Whitelist: apitypes.Rules{Domains: []string{"other.example"}}, Final: "proxy"}
	if _, err := s.applySlot(slot, apitypes.PostureSplit); err == nil {
		t.Fatal("expected error to propagate")
	}
	got := s.wl.Get()
	hasOther, hasAllowed := false, false
	for _, d := range got.Domains {
		if d == "other.example" {
			hasOther = true
		}
		if d == "allowed.example" {
			hasAllowed = true
		}
	}
	if hasOther || !hasAllowed {
		t.Fatalf("whitelist store must stay untouched on ApplyProfile failure: %+v", got)
	}
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

var errFake = fakeErr("apply failed")
