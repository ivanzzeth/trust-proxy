package ruleset

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func writeSet(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDNSSafeLocalSets(t *testing.T) {
	domains := writeSet(t, "cn.json", `{"version":1,"rules":[{"domain_suffix":["taobao.com"]}]}`)
	ips := writeSet(t, "cnip.json", `{"version":1,"rules":[{"ip_cidr":["1.1.1.0/24"]}]}`)
	mixed := writeSet(t, "mixed.json", `{"version":1,"rules":[{"domain_suffix":["a.tp"],"ip_cidr":["1.1.1.0/24"]}]}`)

	local := func(path string) apitypes.RuleSet {
		return apitypes.RuleSet{Tag: "t", Type: "local", Format: "source", Path: path, Enabled: true}
	}
	if !DNSSafe(local(domains)) {
		t.Fatal("domain-only local set must be usable in dns rules")
	}
	if DNSSafe(local(ips)) {
		t.Fatal("ip-only local set must be rejected")
	}
	// A mixed set still triggers resolve-then-verify, so it is rejected too.
	if DNSSafe(local(mixed)) {
		t.Fatal("set with ip_cidr items must be rejected even when it has domains")
	}
	if DNSSafe(local(filepath.Join(t.TempDir(), "missing.json"))) {
		t.Fatal("undecodable set must be rejected (fail safe)")
	}
}

func TestDNSSafeRemoteSets(t *testing.T) {
	remote := func(tag, url string) apitypes.RuleSet {
		return apitypes.RuleSet{Tag: tag, Type: "remote", Format: "binary", URL: url, Enabled: true}
	}
	cases := []struct {
		rs   apitypes.RuleSet
		want bool
	}{
		{remote("geosite-cn", "https://x/sing-geosite/rule-set/geosite-cn.srs"), true},
		{remote("geoip-cn", "https://x/sing-geoip/rule-set/geoip-cn.srs"), false},
		// Unknown remote lists can't be inspected without I/O on the config path:
		// skipped, so they can never trigger resolve-then-verify.
		{remote("my-list", "https://example.invalid/list.srs"), false},
	}
	for _, c := range cases {
		if got := DNSSafe(c.rs); got != c.want {
			t.Fatalf("DNSSafe(%s) = %v, want %v", c.rs.Tag, got, c.want)
		}
	}
	if DNSSafe(apitypes.RuleSet{Tag: "geosite-cn", Type: "remote", URL: "https://x/geosite-cn.srs"}) {
		t.Fatal("disabled set must never enter dns rules")
	}
}

func TestDNSSafeTags(t *testing.T) {
	sets := Sets{Sets: []apitypes.RuleSet{
		{Tag: "geosite-cn", Type: "remote", URL: "https://x/sing-geosite/geosite-cn.srs", Enabled: true},
		{Tag: "geoip-cn", Type: "remote", URL: "https://x/sing-geoip/geoip-cn.srs", Enabled: true},
	}}
	tags := DNSSafeTags(sets)
	if !tags["geosite-cn"] || tags["geoip-cn"] {
		t.Fatalf("DNSSafeTags = %v", tags)
	}
}
