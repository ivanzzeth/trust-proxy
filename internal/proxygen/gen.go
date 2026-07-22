// Package proxygen one-click-generates a sing-box server config plus the
// matching client node (Clash dict) for any supported proxy protocol. Shared
// by the `proxy gen` command and the e2e test.
package proxygen

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Protocols lists the one-click-supported server protocols.
var Protocols = []string{"shadowsocks", "vless-reality", "vless", "vmess", "trojan", "anytls", "hysteria2", "tuic"}

// Options configures generation.
type Options struct {
	Type   string
	Server string // address used in the client node
	Port   int
	SNI    string // TLS/Reality SNI (default www.microsoft.com)
	Name   string
}

// Result holds the generated server config, client Clash node, and (if any) a
// client share link.
type Result struct {
	Server map[string]any
	Client map[string]any
	Share  string
}

// Generate builds configs for o.Type.
func Generate(o Options) (Result, error) {
	host := o.Server
	if host == "" {
		host = "YOUR_SERVER_IP"
	}
	name := o.Name
	if name == "" {
		name = o.Type + "-" + host
	}
	sni := o.SNI
	if sni == "" {
		sni = "www.microsoft.com"
	}
	direct := map[string]any{"type": "direct", "tag": "direct"}
	mkServer := func(inbound map[string]any) map[string]any {
		inbound["tag"] = "in"
		inbound["listen"] = "::"
		inbound["listen_port"] = o.Port
		return map[string]any{"inbounds": []any{inbound}, "outbounds": []any{direct}}
	}
	client := func(typ string) map[string]any {
		return map[string]any{"name": name, "type": typ, "server": host, "port": o.Port}
	}

	switch o.Type {
	case "shadowsocks", "ss":
		key, method := randB64(32), "2022-blake3-aes-256-gcm"
		c := client("shadowsocks")
		c["cipher"], c["password"] = method, key
		return Result{
			Server: mkServer(map[string]any{"type": "shadowsocks", "method": method, "password": key}),
			Client: c,
			Share:  fmt.Sprintf("ss://%s@%s:%d#%s", base64.RawURLEncoding.EncodeToString([]byte(method+":"+key)), host, o.Port, url.QueryEscape(name)),
		}, nil

	case "vless-reality":
		uuid := randUUID()
		priv, pub, err := realityKeypair()
		if err != nil {
			return Result{}, err
		}
		sid := hex.EncodeToString(randBytes(4))
		c := client("vless")
		c["uuid"], c["flow"], c["tls"], c["servername"], c["network"], c["client-fingerprint"] = uuid, "xtls-rprx-vision", true, sni, "tcp", "chrome"
		c["reality-opts"] = map[string]any{"public-key": pub, "short-id": sid}
		return Result{
			Server: mkServer(map[string]any{
				"type":  "vless",
				"users": []any{map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}},
				"tls": map[string]any{"enabled": true, "server_name": sni, "reality": map[string]any{
					"enabled": true, "handshake": map[string]any{"server": sni, "server_port": 443},
					"private_key": priv, "short_id": []string{sid},
				}},
			}),
			Client: c,
			Share:  fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&flow=xtls-rprx-vision&type=tcp#%s", uuid, host, o.Port, sni, pub, sid, url.QueryEscape(name)),
		}, nil

	case "vless":
		uuid := randUUID()
		tls, err := SelfSignedTLS(sni)
		if err != nil {
			return Result{}, err
		}
		c := client("vless")
		c["uuid"], c["tls"], c["servername"], c["skip-cert-verify"] = uuid, true, sni, true
		return Result{Server: mkServer(map[string]any{"type": "vless", "users": []any{map[string]any{"uuid": uuid}}, "tls": tls}), Client: c}, nil

	case "vmess":
		uuid := randUUID()
		tls, err := SelfSignedTLS(sni)
		if err != nil {
			return Result{}, err
		}
		c := client("vmess")
		c["uuid"], c["alterId"], c["cipher"], c["tls"], c["servername"], c["skip-cert-verify"] = uuid, 0, "auto", true, sni, true
		return Result{Server: mkServer(map[string]any{"type": "vmess", "users": []any{map[string]any{"uuid": uuid, "alterId": 0}}, "tls": tls}), Client: c}, nil

	case "trojan":
		pw := randB64(18)
		tls, err := SelfSignedTLS(sni)
		if err != nil {
			return Result{}, err
		}
		c := client("trojan")
		c["password"], c["sni"], c["skip-cert-verify"] = pw, sni, true
		return Result{Server: mkServer(map[string]any{"type": "trojan", "users": []any{map[string]any{"password": pw}}, "tls": tls}), Client: c}, nil

	case "anytls":
		pw := randB64(18)
		tls, err := SelfSignedTLS(sni)
		if err != nil {
			return Result{}, err
		}
		c := client("anytls")
		c["password"], c["sni"], c["skip-cert-verify"], c["client-fingerprint"] = pw, sni, true, "chrome"
		return Result{Server: mkServer(map[string]any{"type": "anytls", "users": []any{map[string]any{"password": pw}}, "tls": tls}), Client: c}, nil

	case "hysteria2", "hy2":
		pw := randB64(18)
		tls, err := SelfSignedTLS(sni)
		if err != nil {
			return Result{}, err
		}
		c := client("hysteria2")
		c["password"], c["sni"], c["skip-cert-verify"] = pw, sni, true
		return Result{Server: mkServer(map[string]any{"type": "hysteria2", "users": []any{map[string]any{"password": pw}}, "tls": tls}), Client: c}, nil

	case "tuic":
		uuid, pw := randUUID(), randB64(18)
		tls, err := SelfSignedTLS(sni)
		if err != nil {
			return Result{}, err
		}
		c := client("tuic")
		c["uuid"], c["password"], c["sni"], c["skip-cert-verify"], c["congestion-controller"] = uuid, pw, sni, true, "bbr"
		return Result{Server: mkServer(map[string]any{"type": "tuic", "users": []any{map[string]any{"uuid": uuid, "password": pw}}, "congestion_control": "bbr", "tls": tls}), Client: c}, nil

	default:
		return Result{}, fmt.Errorf("unsupported type %q; supported: %s", o.Type, strings.Join(Protocols, ", "))
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randB64(n int) string { return base64.StdEncoding.EncodeToString(randBytes(n)) }

func randUUID() string {
	b := randBytes(16)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func realityKeypair() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// SelfSignedTLS returns a sing-box tls block with an inline self-signed cert.
func SelfSignedTLS(sni string) (map[string]any, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return map[string]any{
		"enabled": true, "server_name": sni,
		"certificate": pemLines(certPEM), "key": pemLines(keyPEM),
	}, nil
}

func pemLines(b []byte) []string {
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}
