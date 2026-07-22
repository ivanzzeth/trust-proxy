package proxygen_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/proxy"

	"github.com/ivanzzeth/trust-proxy/internal/proxygen"
	"github.com/ivanzzeth/trust-proxy/internal/subscription"
)

// TestProxyE2E generates a server + client for each protocol, runs both
// in-process, and tunnels an HTTP request through the client -> server to a
// loopback httptest server. Hermetic (no internet). Run with the protocol
// build tags, e.g.:
//
//	go test -tags "with_clash_api with_quic with_utls with_grpc with_gvisor" \
//	    -run TestProxyE2E ./internal/proxygen/
func TestProxyE2E(t *testing.T) {
	const want = "trust-proxy-ok"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, want)
	}))
	defer origin.Close()

	for _, proto := range proxygen.Protocols {
		t.Run(proto, func(t *testing.T) {
			if proto == "vless-reality" {
				t.Skip("reality needs a real external TLS handshake target; verified manually / not hermetic")
			}

			res, err := proxygen.Generate(proxygen.Options{Type: proto, Server: "127.0.0.1", Port: freePort(t), SNI: "example.com"})
			if err != nil {
				t.Fatalf("generate: %v", err)
			}

			srv := startBox(t, res.Server)
			defer srv.Close()

			clientPort := freePort(t)
			clientCfg := clientConfig(t, res.Client, clientPort)
			cli := startBox(t, clientCfg)
			defer cli.Close()

			time.Sleep(300 * time.Millisecond) // let listeners settle

			got := httpGetVia(t, "127.0.0.1:"+itoa(clientPort), origin.URL)
			if got != want {
				t.Fatalf("tunnel returned %q, want %q", got, want)
			}
		})
	}
}

// clientConfig builds a minimal gateway: mixed inbound -> the generated node
// (only outbound, so a broken tunnel fails the test rather than falling back).
func clientConfig(t *testing.T, clashNode map[string]any, mixedPort int) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(clashNode)
	nodes := subscription.Parse(raw)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 parsed node from client dict, got %d", len(nodes))
	}
	var ob map[string]any
	if err := json.Unmarshal(nodes[0].Outbound, &ob); err != nil {
		t.Fatalf("unmarshal node outbound: %v", err)
	}
	ob["tag"] = "node"
	return map[string]any{
		"log":       map[string]any{"level": "error"},
		"inbounds":  []any{map[string]any{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": mixedPort}},
		"outbounds": []any{ob, map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"rules": []any{map[string]any{"action": "sniff"}}, "final": "node"},
	}
}

func startBox(t *testing.T, cfg map[string]any) *box.Box {
	t.Helper()
	b, _ := json.Marshal(cfg)
	ctx := service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger()))
	ctx = include.Context(ctx)
	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, b)
	if err != nil {
		t.Fatalf("parse config: %v\n%s", err, b)
	}
	inst, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("box.Start: %v", err)
	}
	return inst
}

func httpGetVia(t *testing.T, socksAddr, url string) string {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks5 dialer: %v", err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		t.Fatal("socks5 dialer is not a ContextDialer")
	}
	c := &http.Client{Transport: &http.Transport{DialContext: cd.DialContext}, Timeout: 12 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("get via tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
