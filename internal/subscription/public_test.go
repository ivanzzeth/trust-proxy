package subscription

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// The subscription URL is the credential. This is the regression test for a
// measured leak: GET /api/subscriptions used to hand out a live airport link plus
// every node's uuid/password.
func TestPublicCarriesNoCredentials(t *testing.T) {
	sub := apitypes.Subscription{
		ID:   "s1",
		Name: "airport",
		// Shape of a real one: the token is a *subdomain*, not a path.
		URL:       "https://0052a2c573e6d817fd679254378b2063.z7pm-k4ra-9vqd-xc3t-bl6s.sbs/sub?token=abc",
		Content:   "vless://uuid@host:443?security=reality#node",
		Via:       "socks5://user:pass@10.0.0.1:1080",
		UserAgent: "clash-verge/v2.0.0",
		NodeCount: 2,
		Nodes: []apitypes.Node{
			{Tag: "HK-01", Protocol: "vless", Server: "1.2.3.4", Port: 443,
				Outbound: json.RawMessage(`{"type":"vless","uuid":"secret-uuid","reality":{"public_key":"pk"}}`)},
		},
		Applied: true,
	}
	raw, err := json.Marshal(Public(sub))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, secret := range []string{
		"0052a2c573e6d817fd679254378b2063", // the token in the hostname
		"token=abc",
		"secret-uuid",
		"user:pass",
		"vless://uuid@host",
		`"outbound"`,
	} {
		if strings.Contains(body, secret) {
			t.Errorf("the wire form still carries %q:\n%s", secret, body)
		}
	}
	// …while still being useful: name, counts, node identity, state.
	for _, want := range []string{`"name":"airport"`, `"node_count":2`, `"HK-01"`, `"applied":true`, `"has_url":true`, `"has_via":true`} {
		if !strings.Contains(body, want) {
			t.Errorf("the wire form lost %s:\n%s", want, body)
		}
	}
}

// Export is the deliberate opposite of Public: the admin asked for the origin, so
// the URL comes back verbatim. What must *not* come back is the node outbounds —
// recreating a subscription re-fetches those, so shipping them widens the exposure
// for nothing. The second half asserts on the marshalled body rather than on named
// fields, so a credential added to the export type later is caught too.
func TestExportCarriesTheURLAndNoNodeCredentials(t *testing.T) {
	sub := apitypes.Subscription{
		ID:        "s1",
		Name:      "airport",
		URL:       "https://0052a2c573e6d817fd679254378b2063.z7pm-k4ra-9vqd-xc3t-bl6s.sbs/sub?token=abc",
		Via:       "socks5://user:pass@10.0.0.1:1080",
		UserAgent: "clash-verge/v2.0.0",
		NodeCount: 1,
		Nodes: []apitypes.Node{
			{Tag: "HK-01", Protocol: "vless", Server: "1.2.3.4", Port: 443,
				Outbound: json.RawMessage(`{"type":"vless","uuid":"secret-uuid","reality":{"private_key":"secret-pk"}}`)},
		},
	}
	got := Export(sub)
	if got.URL != sub.URL {
		t.Fatalf("Export dropped the URL: %q", got.URL)
	}
	if got.Via != sub.Via || got.UserAgent != sub.UserAgent || got.Name != sub.Name {
		t.Fatalf("Export lost the knobs needed to recreate it: %+v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, secret := range []string{"secret-uuid", "secret-pk", `"outbound"`, "HK-01"} {
		if strings.Contains(body, secret) {
			t.Errorf("the export carries node credentials (%q):\n%s", secret, body)
		}
	}
}

func TestMaskSource(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://0052a2c573e6d817fd679254378b2063.z7pm-k4ra-9vqd-xc3t-bl6s.sbs/sub?token=x", "https://***.z7pm-k4ra-9vqd-xc3t-bl6s.sbs/***"},
		{"https://sub.example.com/link", "https://***.example.com/***"},
		{"http://example.com/a", "http://***.example.com/***"},
		{"file:///Users/ivan/profiles/airport.yaml", "file://***/airport.yaml"},
		{"", ""},
	} {
		if got := MaskSource(tc.in, false); got != tc.want {
			t.Errorf("MaskSource(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := MaskSource("", true); got != "pasted" {
		t.Errorf("pasted source = %q", got)
	}
}

// The store must keep the real thing — the gateway needs the URL to refresh and
// the outbounds to dial. Redaction is a boundary concern only.
func TestStoreStillKeepsTheSecrets(t *testing.T) {
	sub := apitypes.Subscription{
		URL:   "https://real.example/sub",
		Nodes: []apitypes.Node{{Tag: "n", Outbound: json.RawMessage(`{"uuid":"u"}`)}},
	}
	if p := Public(sub); p.Source == sub.URL {
		t.Fatal("Public must not return the raw URL")
	}
	if sub.URL != "https://real.example/sub" || len(sub.Nodes[0].Outbound) == 0 {
		t.Fatal("Public must not mutate the stored subscription")
	}
}
