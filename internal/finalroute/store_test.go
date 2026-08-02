package finalroute

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolve_BuiltinsAndSelfHeal(t *testing.T) {
	if got := Resolve("", nil); got != OutboundDirect {
		t.Fatalf("empty -> %q", got)
	}
	if got := Resolve(OutboundDirect, nil); got != OutboundDirect {
		t.Fatalf("direct -> %q", got)
	}
	if got := Resolve("🇯🇵 JP", []string{"🇯🇵 JP", "Auto"}); got != "🇯🇵 JP" {
		t.Fatalf("live tag -> %q", got)
	}
	if got := Resolve("missing-node", []string{"Auto"}); got != OutboundDirect {
		t.Fatalf("missing tag should self-heal to direct, got %q", got)
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(OutboundProxy); err != nil {
		t.Fatal(err)
	}
	if err := Validate("bad tag"); err == nil {
		t.Fatal("expected whitespace rejection")
	}
}

// An upgrade must not leave CN hosts falling into overseas Final=proxy: the
// abandoned seed is rewritten to direct once.
func TestNewStore_HealsAbandonedProxyDefaultOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "final.json")
	if err := os.WriteFile(path, []byte(`{"outbound":"proxy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Get().Outbound; got != OutboundDirect {
		t.Fatalf("abandoned proxy default healed to %q, want direct", got)
	}

	// Operator then chooses proxy — must stick across reopen.
	if _, err := s.Set(Config{Outbound: OutboundProxy}); err != nil {
		t.Fatal(err)
	}
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.Get().Outbound; got != OutboundProxy {
		t.Fatalf("explicit proxy re-healed to %q", got)
	}
}

func TestNewStore_FreshSeedsDirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "final.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Get().Outbound; got != OutboundDirect {
		t.Fatalf("fresh seed = %q", got)
	}
}
