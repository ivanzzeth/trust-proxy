package subscription

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/metacubex/utls"
	"golang.org/x/net/proxy"
)

// newUTLSClient returns a full http.Client (follows redirects, handles gzip,
// keep-alive, etc. — like clash-verge's reqwest) whose TLS is a Chrome uTLS
// handshake pinned to HTTP/1.1. Earlier we hand-rolled a single req.Write +
// ReadResponse, which did NOT follow redirects — a real bug for subscription
// endpoints that 302 to the actual payload.
//
// If via is set (socks5:// or http://), the TCP connection is made through that
// proxy so the fetch can egress from an IP the airport accepts (a TLS
// fingerprint cannot beat a source-IP reputation block).
func newUTLSClient(via string) *http.Client {
	d := &net.Dialer{Timeout: 15 * time.Second}
	tr := &http.Transport{
		ForceAttemptHTTP2:   false,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 15 * time.Second,
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			raw, err := dialTarget(ctx, d, via, addr)
			if err != nil {
				return nil, err
			}
			uconn, err := chromeHandshakeH1(ctx, raw, host)
			if err != nil {
				raw.Close()
				return nil, err
			}
			return uconn, nil
		},
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
		// default CheckRedirect follows up to 10 redirects
	}
}

// dialTarget opens a TCP conn to addr, directly or through a socks5://|http://
// proxy.
func dialTarget(ctx context.Context, d *net.Dialer, via, addr string) (net.Conn, error) {
	if via == "" {
		return d.DialContext(ctx, "tcp", addr)
	}
	pu, err := url.Parse(via)
	if err != nil {
		return nil, fmt.Errorf("bad --via %q: %w", via, err)
	}
	switch pu.Scheme {
	case "socks5", "socks5h":
		pd, err := proxy.SOCKS5("tcp", pu.Host, nil, d)
		if err != nil {
			return nil, err
		}
		if cd, ok := pd.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		return pd.Dial("tcp", addr)
	case "http", "https":
		return dialHTTPConnect(ctx, d, pu.Host, addr)
	default:
		return nil, fmt.Errorf("unsupported --via scheme %q (use socks5:// or http://)", pu.Scheme)
	}
}

func dialHTTPConnect(ctx context.Context, d *net.Dialer, proxyHost, addr string) (net.Conn, error) {
	c, err := d.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, err
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: make(http.Header)}
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
// to http/1.1 (no Go h2 fingerprint).
func chromeHandshakeH1(ctx context.Context, raw net.Conn, host string) (*utls.UConn, error) {
	cfg := &utls.Config{ServerName: host}
	if spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133); err == nil {
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
