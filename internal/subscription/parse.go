package subscription

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Parse turns a subscription body into nodes. It handles the common formats:
// the whole body may be base64-encoded; the decoded text is one share-link per
// line (vless://, trojan://, ss://, hysteria2://, tuic://, vmess://...).
//
// This is deliberately a lightweight parser that extracts identity fields
// (protocol/server/port/tag) — enough to list and count nodes. Turning nodes
// into full sing-box outbounds (the "apply" step) is a separate concern.
func Parse(body []byte) []apitypes.Node {
	text := strings.TrimSpace(string(body))
	if decoded, ok := tryBase64(text); ok {
		text = decoded
	}

	var nodes []apitypes.Node
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if node, ok := parseLink(line); ok {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func tryBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	// share links contain "://" in plaintext; base64 blobs do not.
	if strings.Contains(s, "://") {
		return "", false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && strings.Contains(string(b), "://") {
			return string(b), true
		}
	}
	return "", false
}

// parseLink parses one share link into a Node. vmess:// carries a base64 JSON
// object; the others are standard URLs (scheme://[user@]host:port#name).
func parseLink(line string) (apitypes.Node, bool) {
	scheme, rest, ok := strings.Cut(line, "://")
	if !ok {
		return apitypes.Node{}, false
	}
	scheme = strings.ToLower(scheme)

	if scheme == "vmess" {
		return parseVMess(rest)
	}

	// generic scheme://[credentials@]host:port[?query][#tag]
	rest, tag, _ := strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	host, portStr, ok := strings.Cut(rest, ":")
	if !ok {
		return apitypes.Node{}, false
	}
	port, _ := strconv.Atoi(strings.TrimRight(portStr, "/"))
	return apitypes.Node{
		Tag:      decodeTag(tag, scheme+"-"+host),
		Protocol: scheme,
		Server:   host,
		Port:     port,
	}, host != ""
}

func parseVMess(b64 string) (apitypes.Node, bool) {
	dec, ok := tryDecodeB64(b64)
	if !ok {
		return apitypes.Node{}, false
	}
	var v struct {
		PS   string `json:"ps"`
		Add  string `json:"add"`
		Port any    `json:"port"`
	}
	if err := json.Unmarshal([]byte(dec), &v); err != nil {
		return apitypes.Node{}, false
	}
	port := 0
	switch p := v.Port.(type) {
	case float64:
		port = int(p)
	case string:
		port, _ = strconv.Atoi(p)
	}
	tag := v.PS
	if tag == "" {
		tag = "vmess-" + v.Add
	}
	return apitypes.Node{Tag: tag, Protocol: "vmess", Server: v.Add, Port: port}, v.Add != ""
}

func tryDecodeB64(s string) (string, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(strings.TrimSpace(s)); err == nil {
			return string(b), true
		}
	}
	return "", false
}

func decodeTag(raw, fallback string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	// tags are often percent-encoded; keep it simple and readable
	if u, err := url.QueryUnescape(raw); err == nil && u != "" {
		return u
	}
	return raw
}
