package posture

import (
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestNewStore_DefaultsSplit(t *testing.T) {
	// Fresh posture.json must come up Split: Strict default-deny bricks k8s
	// nodes under TUN capture (kubelet/DNS/CNI look like ordinary egress).
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "posture.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Active() != apitypes.PostureSplit {
		t.Fatalf("active=%q want split", s.Active())
	}
	slot, err := s.Slot(apitypes.PostureSplit)
	if err != nil {
		t.Fatal(err)
	}
	if slot.Seeded {
		t.Fatal("fresh split slot must not be seeded")
	}
}

func TestSeedSplit_AllPacksAndGeoIP(t *testing.T) {
	slot := SeedSplit()
	if !slot.Seeded {
		t.Fatal("seeded flag")
	}
	if slot.Final != "direct" {
		t.Fatalf("final=%q", slot.Final)
	}
	if len(slot.CustomRules) == 0 {
		t.Fatal("expected pack custom rules")
	}
	packs := map[string]bool{}
	for _, r := range slot.CustomRules {
		if r.Pack != "" {
			packs[r.Pack] = true
		}
	}
	for _, p := range customrules.Presets {
		if len(p.Rules) == 0 {
			continue
		}
		if !packs[p.Name] {
			t.Fatalf("missing pack rules for %q", p.Name)
		}
	}
	tags := map[string]string{}
	for _, rs := range slot.RuleSets {
		tags[rs.Tag] = rs.Role
	}
	if tags["geoip-cn"] == "" {
		t.Fatal("expected geoip-cn route-direct")
	}
	if apitypes.RuleRoleRouteEgress(tags["geosite-cn"]) != "direct" {
		t.Fatalf("geosite-cn should route-direct, got %q", tags["geosite-cn"])
	}
	if !apitypes.RuleRoleGrantsPermit(tags["geosite-cn"]) {
		t.Fatalf("geosite-cn should also permit after China-wide merge, got %q", tags["geosite-cn"])
	}
}

func TestPutSlot_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "posture.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	slot := apitypes.PolicySlot{
		Whitelist: apitypes.Rules{Domains: []string{"work.example"}},
		Final:     "direct",
	}
	if err := s.PutSlot(apitypes.PostureStrict, slot); err != nil {
		t.Fatal(err)
	}
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s2.Slot(apitypes.PostureStrict)
	if len(got.Whitelist.Domains) != 1 || got.Whitelist.Domains[0] != "work.example" {
		t.Fatalf("round-trip wl=%+v", got.Whitelist)
	}
	if got.Final != "direct" {
		t.Fatalf("final=%q", got.Final)
	}
}
