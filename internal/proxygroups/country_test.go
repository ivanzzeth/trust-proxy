package proxygroups

import "testing"

func TestCountry_QuotaLineIsNotGreatBritain(t *testing.T) {
	for _, tag := range []string{
		"130.17 GB | 300 GB",
		"10GB/100GB",
		"Traffic 50.5 GB left",
	} {
		if c := Country(tag); c != "" {
			t.Fatalf("Country(%q) = %q, want \"\" (data-size, not ISO GB)", tag, c)
		}
	}
	// A real Britain node must still resolve.
	if c := Country("🇬🇧 Great Britain丨01"); c != "GB" {
		t.Fatalf("flag GB node: got %q", c)
	}
	if c := Country("GB-London-01"); c != "GB" {
		t.Fatalf("GB-London-01: got %q", c)
	}
}
