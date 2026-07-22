package subscription

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// newUTLSClient returns a standard Go http.Client for fetching subscriptions:
// crypto/tls (negotiates HTTP/2, standard modern cipher suites — the closest
// Go equivalent to clash-verge's reqwest+rustls, which just works), follows
// redirects, handles gzip/keep-alive. We deliberately do NOT spoof a Chrome
// uTLS fingerprint: forcing an inconsistent ClientHello (Chrome ciphers but
// h1-only ALPN) looked more suspicious to the airport's WAF, not less.
//
// If via is set (socks5:// or http://), the connection egresses through that
// proxy (a TLS fingerprint can't beat a source-IP reputation block).
//
// Name kept as newUTLSClient for call-site stability.
func newUTLSClient(via string) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
	}
	if via != "" {
		if err := applyProxy(tr, via); err != nil {
			// fall back to direct; the fetch error will surface the real problem
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

func applyProxy(tr *http.Transport, via string) error {
	pu, err := url.Parse(via)
	if err != nil {
		return fmt.Errorf("bad --via %q: %w", via, err)
	}
	switch pu.Scheme {
	case "http", "https":
		tr.Proxy = http.ProxyURL(pu)
		return nil
	case "socks5", "socks5h":
		pd, err := proxy.SOCKS5("tcp", pu.Host, nil, &net.Dialer{Timeout: 15 * time.Second})
		if err != nil {
			return err
		}
		if cd, ok := pd.(proxy.ContextDialer); ok {
			tr.DialContext = cd.DialContext
			return nil
		}
		tr.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
			return pd.Dial(network, addr)
		}
		return nil
	default:
		return fmt.Errorf("unsupported --via scheme %q (use socks5:// or http://)", pu.Scheme)
	}
}
