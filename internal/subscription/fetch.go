package subscription

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"time"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/http2"
)

// newUTLSClient returns an http.Client whose TLS handshake mimics Chrome (via
// uTLS). Airports often fingerprint the client (JA3/JA4 + HTTP behaviour) and
// only serve their subscription to real clients (clash/mihomo/browsers); a
// plain Go net/http fetch is reset or handed a "risk network" page. Mimicking
// Chrome lets trust-proxy fetch subscriptions on its own — no external client.
func newUTLSClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &utlsRoundTripper{dialer: &net.Dialer{Timeout: 15 * time.Second}},
	}
}

type utlsRoundTripper struct {
	dialer *net.Dialer
}

func (rt *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only HTTPS goes through uTLS; plain HTTP uses the default transport.
	if req.URL.Scheme != "https" {
		return http.DefaultTransport.RoundTrip(req)
	}

	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	raw, err := rt.dialer.DialContext(req.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(raw, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
	if err := uconn.HandshakeContext(req.Context()); err != nil {
		raw.Close()
		return nil, err
	}

	if uconn.ConnectionState().NegotiatedProtocol == "h2" {
		cc, err := (&http2.Transport{}).NewClientConn(uconn)
		if err != nil {
			uconn.Close()
			return nil, err
		}
		return cc.RoundTrip(req)
	}

	// HTTP/1.1: one-shot request/response over the uTLS conn.
	if err := req.Write(uconn); err != nil {
		uconn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(uconn), req)
	if err != nil {
		uconn.Close()
		return nil, err
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: uconn}
	return resp, nil
}

// connClosingBody closes the underlying uTLS conn when the response body is
// closed (no connection pooling for these occasional fetches).
type connClosingBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *connClosingBody) Close() error {
	err := b.ReadCloser.Close()
	b.conn.Close()
	return err
}
