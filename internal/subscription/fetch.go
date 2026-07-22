package subscription

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/proxy"
)

// newUTLSClient returns an http.Client whose TLS handshake mimics Chrome (via
// uTLS) AND forces HTTP/1.1, so subscription fetches look like a browser and
// avoid Go's distinctive HTTP/2 fingerprint. If via is non-empty (socks5:// or
// http://) the TCP connection is made through that proxy, so the fetch can
// egress from an IP the airport accepts (a datacenter/VPN egress is often
// flagged; the fingerprint can't beat a source-IP reputation block).
func newUTLSClient(via string) *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &utlsRoundTripper{dialer: &net.Dialer{Timeout: 15 * time.Second}, via: via},
	}
}

type utlsRoundTripper struct {
	dialer *net.Dialer
	via    string
}

func (rt *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return http.DefaultTransport.RoundTrip(req)
	}

	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	target := net.JoinHostPort(host, port)

	raw, err := rt.dialTarget(req.Context(), target)
	if err != nil {
		return nil, err
	}
	uconn, err := chromeHandshakeH1(req.Context(), raw, host)
	if err != nil {
		raw.Close()
		return nil, err
	}

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

// dialTarget opens a TCP conn to addr, directly or through rt.via.
func (rt *utlsRoundTripper) dialTarget(ctx context.Context, addr string) (net.Conn, error) {
	if rt.via == "" {
		return rt.dialer.DialContext(ctx, "tcp", addr)
	}
	pu, err := url.Parse(rt.via)
	if err != nil {
		return nil, fmt.Errorf("bad --via %q: %w", rt.via, err)
	}
	switch pu.Scheme {
	case "socks5", "socks5h":
		d, err := proxy.SOCKS5("tcp", pu.Host, nil, rt.dialer)
		if err != nil {
			return nil, err
		}
		if cd, ok := d.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		return d.Dial("tcp", addr)
	case "http", "https":
		return rt.dialHTTPConnect(ctx, pu.Host, addr)
	default:
		return nil, fmt.Errorf("unsupported --via scheme %q (use socks5:// or http://)", pu.Scheme)
	}
}

// dialHTTPConnect establishes a tunnel to addr through an HTTP proxy.
func (rt *utlsRoundTripper) dialHTTPConnect(ctx context.Context, proxyHost, addr string) (net.Conn, error) {
	c, err := rt.dialer.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("http proxy CONNECT: %s", resp.Status)
	}
	return c, nil
}

// chromeHandshakeH1 does a Chrome-fingerprinted TLS handshake with ALPN pinned
// to http/1.1 (so the server never negotiates h2 and we never expose Go's h2
// fingerprint).
func chromeHandshakeH1(ctx context.Context, raw net.Conn, host string) (*utls.UConn, error) {
	cfg := &utls.Config{ServerName: host}
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err == nil {
		for _, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
			}
		}
		u := utls.UClient(raw, cfg, utls.HelloCustom)
		if err := u.ApplyPreset(&spec); err == nil {
			if err := u.HandshakeContext(ctx); err == nil {
				return u, nil
			}
		}
	}
	u := utls.UClient(raw, cfg, utls.HelloChrome_Auto)
	if err := u.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

type connClosingBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *connClosingBody) Close() error {
	err := b.ReadCloser.Close()
	b.conn.Close()
	return err
}
