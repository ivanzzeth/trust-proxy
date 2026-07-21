package subscription

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Parse turns a subscription body into nodes, each carrying a full sing-box
// outbound. It handles three shapes, in order:
//  1. a sing-box JSON config -> take its outbounds directly (lossless);
//  2. a base64 blob of share links -> decode then parse per line;
//  3. plain share links, one per line (vless/trojan/ss/vmess/hysteria2/tuic).
//
// Clash YAML is not yet supported (request with a sing-box or share-link UA).
func Parse(body []byte) []apitypes.Node {
	text := strings.TrimSpace(string(body))

	if nodes, ok := parseSingBoxJSON(text); ok {
		return nodes
	}
	if nodes, ok := parseClashYAML(text); ok {
		return nodes
	}
	if decoded, ok := tryBase64Blob(text); ok {
		text = decoded
	}

	var nodes []apitypes.Node
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "://") {
			continue
		}
		if proto, server, port, ob, ok := linkToOutbound(line); ok {
			raw, _ := json.Marshal(ob)
			nodes = append(nodes, apitypes.Node{
				Tag: tagOf(ob), Protocol: proto, Server: server, Port: port, Outbound: raw,
			})
		}
	}
	return nodes
}

func parseSingBoxJSON(text string) ([]apitypes.Node, bool) {
	if !strings.HasPrefix(text, "{") {
		return nil, false
	}
	var cfg struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(text), &cfg); err != nil || len(cfg.Outbounds) == 0 {
		return nil, false
	}
	skip := map[string]bool{"direct": true, "block": true, "dns": true, "selector": true, "urltest": true}
	var nodes []apitypes.Node
	for _, raw := range cfg.Outbounds {
		var meta struct {
			Type   string `json:"type"`
			Tag    string `json:"tag"`
			Server string `json:"server"`
			Port   int    `json:"server_port"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if meta.Type == "" || skip[meta.Type] {
			continue
		}
		nodes = append(nodes, apitypes.Node{
			Tag: meta.Tag, Protocol: meta.Type, Server: meta.Server, Port: meta.Port, Outbound: raw,
		})
	}
	return nodes, len(nodes) > 0
}

func parseClashYAML(text string) ([]apitypes.Node, bool) {
	if !strings.Contains(text, "proxies:") {
		return nil, false
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil || len(doc.Proxies) == 0 {
		return nil, false
	}
	var nodes []apitypes.Node
	for _, p := range doc.Proxies {
		if proto, server, port, ob, ok := clashProxyToOutbound(p); ok {
			raw, _ := json.Marshal(ob)
			nodes = append(nodes, apitypes.Node{
				Tag: tagOf(ob), Protocol: proto, Server: server, Port: port, Outbound: raw,
			})
		}
	}
	return nodes, len(nodes) > 0
}

func tryBase64Blob(s string) (string, bool) {
	if strings.Contains(s, "://") {
		return "", false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(strings.TrimSpace(s)); err == nil && strings.Contains(string(b), "://") {
			return string(b), true
		}
	}
	return "", false
}

func tagOf(ob map[string]any) string {
	if t, ok := ob["tag"].(string); ok {
		return t
	}
	return ""
}
