package finalroute

import "testing"

func TestResolve_BuiltinsAndSelfHeal(t *testing.T) {
	if got := Resolve("", nil); got != OutboundProxy {
		t.Fatalf("empty -> %q", got)
	}
	if got := Resolve(OutboundDirect, nil); got != OutboundDirect {
		t.Fatalf("direct -> %q", got)
	}
	if got := Resolve("🇯🇵 JP", []string{"🇯🇵 JP", "Auto"}); got != "🇯🇵 JP" {
		t.Fatalf("live tag -> %q", got)
	}
	if got := Resolve("missing-node", []string{"Auto"}); got != OutboundProxy {
		t.Fatalf("missing tag should self-heal to proxy, got %q", got)
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
