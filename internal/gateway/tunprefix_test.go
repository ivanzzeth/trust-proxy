package gateway

import (
	"net/netip"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// The prefixes we hand the host-level watcher have to be the prefixes the tun
// interface actually carries. They were two separate lists once, and the second
// one silently kept 172.19.0.1/30 after the inbound moved to 198.18.0.1/30 — so
// the watcher looked for a network nobody was using, found no interface holding
// it, and reported "traffic is not being captured" on every poll of a tunnel
// that was working. The only way to keep them equal is to read one from the
// other's output, which is what this does: it takes the `address` field out of
// the config we really build.
func addressesFromInbound(t *testing.T, tun apitypes.TUNConfig) []netip.Prefix {
	t.Helper()
	in := buildTUNInbound(tun)
	raw, ok := in["address"].([]string)
	if !ok {
		t.Fatalf("tun inbound has no []string address field: %#v", in["address"])
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, a := range raw {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			t.Fatalf("tun inbound address %q does not parse: %v", a, err)
		}
		out = append(out, p.Masked())
	}
	return out
}

func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTunPrefixesMatchTheAddressesTheInboundGets(t *testing.T) {
	cases := []struct {
		name string
		tun  apitypes.TUNConfig
	}{
		{"default (store leaves address empty)", apitypes.TUNConfig{Stack: "gvisor", StrictRoute: true}},
		{"custom address", apitypes.TUNConfig{Stack: "gvisor", Address: []string{"10.77.0.1/30"}}},
		{"custom v4+v6", apitypes.TUNConfig{Stack: "mixed", Address: []string{"10.77.0.1/30", "fdaa::1/126"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{tun: tc.tun}
			got, want := m.TunPrefixes(), addressesFromInbound(t, tc.tun)
			if len(got) == 0 {
				t.Fatal("TunPrefixes returned nothing: the watcher would have no way to " +
					"recognise our tunnel and would report it missing forever")
			}
			if !samePrefixes(got, want) {
				t.Fatalf("TunPrefixes() = %v, but the tun inbound gets %v — the watcher would "+
					"look for a network the interface does not carry", got, want)
			}
		})
	}
}

// The default has to stay off Docker's 172.16/12 pools, which is why it is
// 198.18/15 (see apitypes.DefaultTUNAddresses). Pinning it here means a change
// to that constant is a deliberate act rather than a side effect.
func TestDefaultTunPrefixAvoidsDockerPools(t *testing.T) {
	m := &Manager{tun: apitypes.TUNConfig{Stack: "gvisor"}}
	docker := netip.MustParsePrefix("172.16.0.0/12")
	found := false
	for _, p := range m.TunPrefixes() {
		if !p.Addr().Is4() {
			continue
		}
		found = true
		if docker.Overlaps(p) {
			t.Fatalf("default TUN prefix %v overlaps Docker's %v: container bridges and our "+
				"tunnel would fight over the same addresses", p, docker)
		}
	}
	if !found {
		t.Fatal("no IPv4 prefix in the default TUN addresses")
	}
}
