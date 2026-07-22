package cmd

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/spf13/cobra"

	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run or generate a proxy SERVER (self-hosted exit node)",
}

// ---- proxy run ----

var proxyRunConfig string

var proxyRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a sing-box server config (inbound protocol -> direct out)",
	RunE: func(cmd *cobra.Command, args []string) error {
		content, err := os.ReadFile(proxyRunConfig)
		if err != nil {
			return err
		}
		ctx := service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger()))
		ctx = include.Context(ctx)
		options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, content)
		if err != nil {
			return err
		}
		inst, err := box.New(box.Options{Context: ctx, Options: options})
		if err != nil {
			return err
		}
		if err := inst.Start(); err != nil {
			return err
		}
		defer inst.Close()
		log.StdLogger().Info("proxy server started")
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		return nil
	},
}

// ---- proxy gen ----

var (
	genType   string
	genPort   int
	genServer string
	genSNI    string
	genName   string
	genOut    string
)

// Protocols supports one-click server generation. TLS-based ones get an inline
// self-signed cert (client uses skip-cert-verify); vless-reality needs no cert.
var Protocols = []string{"shadowsocks", "vless-reality", "vless", "vmess", "trojan", "anytls", "hysteria2", "tuic"}

var proxyGenCmd = &cobra.Command{
	Use:   "gen",
	Short: "One-click generate a server config + client node for any protocol",
	Long:  "Supported --type: " + strings.Join(Protocols, " | "),
	RunE: func(cmd *cobra.Command, args []string) error {
		server, clientClash, share, err := generate()
		if err != nil {
			return err
		}
		srvJSON, _ := json.MarshalIndent(server, "", "  ")
		if genOut != "" {
			if err := os.WriteFile(genOut, srvJSON, 0o644); err != nil {
				return err
			}
			fmt.Printf("✓ server config -> %s\n  run it:  trust-proxy proxy run -c %s\n\n", genOut, genOut)
		} else {
			fmt.Printf("=== server config (trust-proxy proxy run -c <file>) ===\n%s\n\n", srvJSON)
		}
		clashJSON, _ := json.MarshalIndent(clientClash, "", "  ")
		fmt.Printf("=== client node — paste into trust-proxy (订阅→手动/粘贴) ===\n%s\n", clashJSON)
		if share != "" {
			fmt.Printf("\n=== client share link ===\n%s\n", share)
		}
		return nil
	},
}

func generate() (server, clientClash map[string]any, share string, err error) {
	host := genServer
	if host == "" {
		host = "YOUR_SERVER_IP"
	}
	name := genName
	if name == "" {
		name = genType + "-" + host
	}
	sni := genSNI
	if sni == "" {
		sni = "www.microsoft.com"
	}
	direct := map[string]any{"type": "direct", "tag": "direct"}
	mkServer := func(inbound map[string]any) map[string]any {
		inbound["tag"] = "in"
		inbound["listen"] = "::"
		inbound["listen_port"] = genPort
		return map[string]any{"inbounds": []any{inbound}, "outbounds": []any{direct}}
	}
	clientBase := func(typ string) map[string]any {
		return map[string]any{"name": name, "type": typ, "server": host, "port": genPort}
	}

	switch genType {
	case "shadowsocks", "ss":
		key, method := randB64(32), "2022-blake3-aes-256-gcm"
		server = mkServer(map[string]any{"type": "shadowsocks", "method": method, "password": key})
		c := clientBase("shadowsocks")
		c["cipher"], c["password"] = method, key
		share = fmt.Sprintf("ss://%s@%s:%d#%s", base64.RawURLEncoding.EncodeToString([]byte(method+":"+key)), host, genPort, url.QueryEscape(name))
		return server, c, share, nil

	case "vless-reality":
		uuid := randUUID()
		priv, pub, e := realityKeypair()
		if e != nil {
			return nil, nil, "", e
		}
		sid := hex.EncodeToString(randBytes(4))
		server = mkServer(map[string]any{
			"type":  "vless",
			"users": []any{map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}},
			"tls": map[string]any{"enabled": true, "server_name": sni, "reality": map[string]any{
				"enabled": true, "handshake": map[string]any{"server": sni, "server_port": 443},
				"private_key": priv, "short_id": []string{sid},
			}},
		})
		c := clientBase("vless")
		c["uuid"], c["flow"], c["tls"], c["servername"], c["network"], c["client-fingerprint"] = uuid, "xtls-rprx-vision", true, sni, "tcp", "chrome"
		c["reality-opts"] = map[string]any{"public-key": pub, "short-id": sid}
		share = fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&flow=xtls-rprx-vision&type=tcp#%s", uuid, host, genPort, sni, pub, sid, url.QueryEscape(name))
		return server, c, share, nil

	case "vless":
		uuid := randUUID()
		tls, e := selfSignedTLS(sni)
		if e != nil {
			return nil, nil, "", e
		}
		server = mkServer(map[string]any{"type": "vless", "users": []any{map[string]any{"uuid": uuid}}, "tls": tls})
		c := clientBase("vless")
		c["uuid"], c["tls"], c["servername"], c["skip-cert-verify"] = uuid, true, sni, true
		return server, c, "", nil

	case "vmess":
		uuid := randUUID()
		tls, e := selfSignedTLS(sni)
		if e != nil {
			return nil, nil, "", e
		}
		server = mkServer(map[string]any{"type": "vmess", "users": []any{map[string]any{"uuid": uuid, "alterId": 0}}, "tls": tls})
		c := clientBase("vmess")
		c["uuid"], c["alterId"], c["cipher"], c["tls"], c["servername"], c["skip-cert-verify"] = uuid, 0, "auto", true, sni, true
		return server, c, "", nil

	case "trojan":
		pw := randB64(18)
		tls, e := selfSignedTLS(sni)
		if e != nil {
			return nil, nil, "", e
		}
		server = mkServer(map[string]any{"type": "trojan", "users": []any{map[string]any{"password": pw}}, "tls": tls})
		c := clientBase("trojan")
		c["password"], c["sni"], c["skip-cert-verify"] = pw, sni, true
		return server, c, "", nil

	case "anytls":
		pw := randB64(18)
		tls, e := selfSignedTLS(sni)
		if e != nil {
			return nil, nil, "", e
		}
		server = mkServer(map[string]any{"type": "anytls", "users": []any{map[string]any{"password": pw}}, "tls": tls})
		c := clientBase("anytls")
		c["password"], c["sni"], c["skip-cert-verify"], c["client-fingerprint"] = pw, sni, true, "chrome"
		return server, c, "", nil

	case "hysteria2", "hy2":
		pw := randB64(18)
		tls, e := selfSignedTLS(sni)
		if e != nil {
			return nil, nil, "", e
		}
		server = mkServer(map[string]any{"type": "hysteria2", "users": []any{map[string]any{"password": pw}}, "tls": tls})
		c := clientBase("hysteria2")
		c["password"], c["sni"], c["skip-cert-verify"] = pw, sni, true
		return server, c, "", nil

	case "tuic":
		uuid, pw := randUUID(), randB64(18)
		tls, e := selfSignedTLS(sni)
		if e != nil {
			return nil, nil, "", e
		}
		server = mkServer(map[string]any{"type": "tuic", "users": []any{map[string]any{"uuid": uuid, "password": pw}}, "congestion_control": "bbr", "tls": tls})
		c := clientBase("tuic")
		c["uuid"], c["password"], c["sni"], c["skip-cert-verify"], c["congestion-controller"] = uuid, pw, sni, true, "bbr"
		return server, c, "", nil

	default:
		return nil, nil, "", fmt.Errorf("unsupported --type %q; supported: %s", genType, strings.Join(Protocols, ", "))
	}
}

// ---- crypto helpers ----

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

// selfSignedTLS returns a sing-box tls block with an inline self-signed cert.
func selfSignedTLS(sni string) (map[string]any, error) {
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
		"enabled":     true,
		"server_name": sni,
		"certificate": pemLines(certPEM),
		"key":         pemLines(keyPEM),
	}, nil
}

func pemLines(b []byte) []string {
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func init() {
	proxyRunCmd.Flags().StringVarP(&proxyRunConfig, "config", "c", "server.json", "server config path")
	f := proxyGenCmd.Flags()
	f.StringVar(&genType, "type", "vless-reality", strings.Join(Protocols, " | "))
	f.IntVar(&genPort, "port", 443, "listen port")
	f.StringVar(&genServer, "server", "", "server address for the client link")
	f.StringVar(&genSNI, "sni", "", "TLS/Reality SNI (default www.microsoft.com)")
	f.StringVar(&genName, "name", "", "node name")
	f.StringVar(&genOut, "out", "", "write server config to file (default stdout)")
	proxyCmd.AddCommand(proxyRunCmd, proxyGenCmd)
}
