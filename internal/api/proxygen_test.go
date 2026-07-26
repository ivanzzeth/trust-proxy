package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/subscription"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func genPost(t *testing.T, body string) (*httptest.ResponseRecorder, apitypes.ProxyGenResult) {
	t.Helper()
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/proxy-gen", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleProxyGen(rec, req)
	var out apitypes.ProxyGenResult
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestProxyGenReturnsBothHalvesAndDeployCommands(t *testing.T) {
	rec, res := genPost(t, `{"type":"vless-reality","server":"203.0.113.9","port":8443,"name":"tokyo"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if res.Server == nil || res.Client == nil {
		t.Fatal("both the server config and the client node must come back")
	}
	if res.Client["server"] != "203.0.113.9" || res.Client["name"] != "tokyo" {
		t.Fatalf("client node does not reflect the request: %v", res.Client)
	}
	if port, _ := res.Client["port"].(float64); int(port) != 8443 {
		t.Fatalf("client port %v, want 8443", res.Client["port"])
	}
	if !strings.Contains(res.GenCommand, "--type vless-reality") || !strings.Contains(res.GenCommand, "--port 8443") {
		t.Fatalf("gen command does not reproduce the request: %s", res.GenCommand)
	}
	if !strings.Contains(res.InstallScript, "proxy run -c server.json -d") {
		t.Fatalf("install script does not start the server: %s", res.InstallScript)
	}
	// The whole point of generating once: the reality public key the client is
	// given must be the pair of the private key the server config carries.
	pub, _ := res.Client["reality-opts"].(map[string]any)
	if pub == nil || pub["public-key"] == "" {
		t.Fatalf("client node lacks the reality public key: %v", res.Client)
	}
	if !strings.Contains(res.InstallScript, "private_key") {
		t.Fatal("install script must carry the server's private key")
	}
}

// A node pointing at a placeholder or a mangled address would be imported and
// then quietly fail to dial, so the API refuses it rather than generating junk.
func TestProxyGenRejectsBadInput(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"no type", `{"server":"203.0.113.9"}`},
		{"unknown type", `{"type":"wireguard","server":"203.0.113.9"}`},
		{"no server", `{"type":"trojan"}`},
		{"url as server", `{"type":"trojan","server":"https://a.example"}`},
		{"host:port as server", `{"type":"trojan","server":"a.example:443"}`},
		{"quote in server", `{"type":"trojan","server":"a.example'; rm -rf /"}`},
		{"port out of range", `{"type":"trojan","server":"a.example","port":70000}`},
		{"not json", `nope`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, _ := genPost(t, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d (want 400): %s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), `"error"`) {
				t.Fatalf("errors must surface as {\"error\":…}: %s", rec.Body)
			}
		})
	}
}

func TestProxyGenPortDefaultsTo443(t *testing.T) {
	_, res := genPost(t, `{"type":"trojan","server":"a.example"}`)
	if port, _ := res.Client["port"].(float64); int(port) != 443 {
		t.Fatalf("port %v, want the 443 default", res.Client["port"])
	}
}

func TestProxyProtocolsIsABareArray(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleProxyProtocols(rec, httptest.NewRequest(http.MethodGet, "/api/proxy-gen/protocols", nil))
	var got []string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("not a bare array: %s", rec.Body)
	}
	if len(got) == 0 {
		t.Fatal("no protocols listed")
	}
}

// The generated client node is only useful if the importer accepts it, so assert
// the shape end-to-end rather than trusting that it looks like a Clash dict.
func TestGeneratedClientNodeImportsAsANode(t *testing.T) {
	for _, typ := range []string{"shadowsocks", "vless-reality", "vmess", "trojan", "anytls", "hysteria2", "tuic"} {
		t.Run(typ, func(t *testing.T) {
			_, res := genPost(t, `{"type":"`+typ+`","server":"203.0.113.9","port":443,"name":"gen"}`)
			raw, err := json.Marshal(res.Client)
			if err != nil {
				t.Fatal(err)
			}
			nodes := subscription.Parse(raw)
			if len(nodes) != 1 {
				t.Fatalf("importer parsed %d nodes from the generated %s node: %s", len(nodes), typ, raw)
			}
			if nodes[0].Server != "203.0.113.9" || nodes[0].Port != 443 {
				t.Fatalf("imported node lost its address: %+v", nodes[0])
			}
		})
	}
}
