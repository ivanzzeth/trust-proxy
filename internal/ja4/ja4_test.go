package ja4

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
)

// captureHello runs a real TLS client against a listener that keeps the bytes,
// so the parser is exercised against a handshake an actual TLS stack produced
// rather than one hand-assembled to match the parser's assumptions.
func captureHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- nil
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := io.ReadAtLeast(conn, buf, 64)
		done <- buf[:n]
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = tls.Client(c, cfg).Handshake() // fails: nobody answers. We only want the hello.
	hello := <-done
	if len(hello) == 0 {
		t.Fatal("captured no ClientHello")
	}
	return hello
}

func TestComputeRealClientHello(t *testing.T) {
	hello := captureHello(t, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}})
	fp, err := Compute(hello, "t")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	t.Logf("ja4=%s version=%s alpn=%s ciphers=%d exts=%d", fp.JA4, fp.Version, fp.ALPN, fp.Ciphers, fp.Exts)

	parts := strings.Split(fp.JA4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 %q must have three underscore-separated parts", fp.JA4)
	}
	if len(parts[0]) != 10 {
		t.Fatalf("part a = %q, want 10 characters (proto+version+sni+2+2+alpn)", parts[0])
	}
	if len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Fatalf("hash parts = %q/%q, want 12 characters each", parts[1], parts[2])
	}
	if !strings.HasPrefix(fp.JA4, "t13d") {
		t.Fatalf("JA4 = %q, want TCP + TLS1.3 + SNI present", fp.JA4)
	}
	if !strings.HasSuffix(parts[0], "h2") {
		t.Fatalf("part a = %q, want the first ALPN (h2) in the last two characters", parts[0])
	}
	if !fp.SNI || fp.Ciphers == 0 || fp.Exts == 0 {
		t.Fatalf("parsed nothing useful: %+v", fp)
	}
}

// No SNI must show as "i", and the ALPN slot as "00" when none is offered.
func TestComputeWithoutSNIOrALPN(t *testing.T) {
	hello := captureHello(t, &tls.Config{InsecureSkipVerify: true})
	fp, err := Compute(hello, "t")
	if err != nil {
		t.Fatal(err)
	}
	if fp.SNI {
		t.Fatalf("SNI reported present: %s", fp.JA4)
	}
	if !strings.HasPrefix(fp.JA4, "t13i") {
		t.Fatalf("JA4 = %q, want the no-SNI marker", fp.JA4)
	}
	if !strings.HasSuffix(strings.Split(fp.JA4, "_")[0], "00") {
		t.Fatalf("JA4 = %q, want 00 in the ALPN slot", fp.JA4)
	}
}

// The same stack must fingerprint identically across connections — otherwise the
// whole idea (spot the odd client out) collapses.
func TestFingerprintIsStableForTheSameClient(t *testing.T) {
	cfg := &tls.Config{ServerName: "example.com", NextProtos: []string{"h2"}}
	a, err := Compute(captureHello(t, cfg), "t")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compute(captureHello(t, cfg), "t")
	if err != nil {
		t.Fatal(err)
	}
	if a.JA4 != b.JA4 {
		t.Fatalf("same client fingerprinted differently: %s vs %s", a.JA4, b.JA4)
	}
}

// A different offered cipher set is a different stack, and must be visible.
func TestDifferentClientsDiffer(t *testing.T) {
	base, err := Compute(captureHello(t, &tls.Config{ServerName: "example.com"}), "t")
	if err != nil {
		t.Fatal(err)
	}
	limited, err := Compute(captureHello(t, &tls.Config{
		ServerName:   "example.com",
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}), "t")
	if err != nil {
		t.Fatal(err)
	}
	if base.JA4 == limited.JA4 {
		t.Fatalf("a TLS1.2, single-cipher client fingerprinted the same as a default one: %s", base.JA4)
	}
	if !strings.HasPrefix(limited.JA4, "t12") {
		t.Fatalf("limited client = %q, want the TLS1.2 marker", limited.JA4)
	}
}

// GREASE is random padding; counting or hashing it would make every connection
// unique and the fingerprint useless.
func TestGREASEIsIgnored(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa} {
		if !isGREASE(v) {
			t.Fatalf("%04x must be recognised as GREASE", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0000, 0xc02f, 0x0a0b, 0x1a2a} {
		if isGREASE(v) {
			t.Fatalf("%04x must not be treated as GREASE", v)
		}
	}
}

func TestRejectsNonClientHello(t *testing.T) {
	if _, err := Compute([]byte("GET / HTTP/1.1\r\n\r\n"), "t"); err == nil {
		t.Fatal("plain HTTP must not produce a fingerprint")
	}
	if _, err := Compute([]byte{0x16, 0x03, 0x01}, "t"); err == nil {
		t.Fatal("a truncated record must not produce a fingerprint")
	}
}
