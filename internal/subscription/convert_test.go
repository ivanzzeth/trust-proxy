package subscription

import "testing"

// Clash socks5 / http proxies must parse into sing-box socks/http outbounds —
// airports and Surge-exported profiles commonly include these alongside ss/vmess.
func TestClashProxyToOutbound_SocksHTTP(t *testing.T) {
	cases := []struct {
		name     string
		in       map[string]any
		wantType string
		wantAuth bool
	}{
		{"socks5 no auth", map[string]any{"type": "socks5", "server": "1.2.3.4", "port": 1080}, "socks", false},
		{"socks5 auth", map[string]any{"type": "socks5", "server": "1.2.3.4", "port": 1080, "username": "u", "password": "p"}, "socks", true},
		{"http", map[string]any{"type": "http", "server": "1.2.3.4", "port": 8080, "username": "u", "password": "p"}, "http", true},
		{"https tls", map[string]any{"type": "https", "server": "1.2.3.4", "port": 443}, "http", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, ob, ok := clashProxyToOutbound(tc.in)
			if !ok {
				t.Fatalf("expected ok for %v", tc.in)
			}
			if ob["type"] != tc.wantType {
				t.Fatalf("type = %v, want %s", ob["type"], tc.wantType)
			}
			_, hasUser := ob["username"]
			if hasUser != tc.wantAuth {
				t.Fatalf("auth present = %v, want %v", hasUser, tc.wantAuth)
			}
			if tc.in["type"] == "https" && ob["tls"] == nil {
				t.Fatal("https should carry a tls block")
			}
		})
	}
}
