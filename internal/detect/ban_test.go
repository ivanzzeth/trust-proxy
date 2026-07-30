package detect

import "testing"

// banEvent decides what reaches the quarantine store. Handing a hostname over as
// the ip argument got the entry rejected outright, so an exfil kill left no trace
// in the UI. Proxy/socks mode reaches this path routinely (sing-box dials by
// name), so it is not a corner case.
func TestBanEventClassifiesDestination(t *testing.T) {
	cases := []struct {
		name, host, dest string
		wantDomain       string
		wantIP           string
	}{
		{"name dialed, unresolved dest", "upload.example.com", "upload.example.com:443", "upload.example.com", ""},
		{"name dialed, resolved dest", "upload.example.com", "93.184.216.34:443", "upload.example.com", "93.184.216.34"},
		{"bare ip", "203.0.113.7", "203.0.113.7:8080", "", "203.0.113.7"},
		{"no host, unresolved dest", "", "upload.example.com:443", "upload.example.com", ""},
		{"ipv6 dest", "", "[2001:db8::1]:443", "", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(8)
			var gotDomain, gotIP string
			called := false
			e.SetOnBan(func(domain, ip, reason string) {
				gotDomain, gotIP, called = domain, ip, true
			})
			e.banEvent(&Event{Host: tc.host, Destination: tc.dest}, "r")
			if !called {
				t.Fatal("no ban emitted: the destination would be killed but never listed")
			}
			if gotDomain != tc.wantDomain || gotIP != tc.wantIP {
				t.Fatalf("got domain=%q ip=%q, want domain=%q ip=%q", gotDomain, gotIP, tc.wantDomain, tc.wantIP)
			}
		})
	}
}
