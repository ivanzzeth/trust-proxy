package subscription

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// linkToOutbound converts one share link into a sing-box outbound object.
// Supported: vless, trojan, shadowsocks (ss), vmess, hysteria2 (hy2), tuic.
// Returns (protocol, server, port, outbound-json, ok).
func linkToOutbound(line string) (proto, server string, port int, ob map[string]any, ok bool) {
	scheme, rest, found := strings.Cut(line, "://")
	if !found {
		return "", "", 0, nil, false
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return fromVLESS(rest)
	case "trojan":
		return fromTrojan(rest)
	case "ss", "shadowsocks":
		return fromShadowsocks(rest)
	case "vmess":
		return fromVMess(rest)
	case "hysteria2", "hy2":
		return fromHysteria2(rest)
	case "tuic":
		return fromTUIC(rest)
	default:
		return "", "", 0, nil, false
	}
}

// parseURLParts splits "[cred@]host:port[?query][#tag]".
func parseURLParts(rest string) (cred, host string, port int, q url.Values, tag string) {
	rest, frag, _ := strings.Cut(rest, "#")
	tag, _ = url.QueryUnescape(frag)
	var query string
	rest, query, _ = strings.Cut(rest, "?")
	q, _ = url.ParseQuery(query)
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		cred = rest[:at]
		rest = rest[at+1:]
	}
	host, portStr, _ := strings.Cut(rest, ":")
	port, _ = strconv.Atoi(strings.TrimRight(portStr, "/"))
	return cred, host, port, q, tag
}

// tlsBlock builds a sing-box tls object from common query params.
func tlsBlock(host string, q url.Values) map[string]any {
	security := q.Get("security")
	sni := first(q.Get("sni"), q.Get("peer"), q.Get("host"))
	if sni == "" {
		sni = host
	}
	switch security {
	case "reality":
		tls := map[string]any{"enabled": true, "server_name": sni}
		reality := map[string]any{"enabled": true, "public_key": q.Get("pbk")}
		if sid := q.Get("sid"); sid != "" {
			reality["short_id"] = sid
		}
		tls["reality"] = reality
		if fp := q.Get("fp"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		return tls
	case "tls", "xtls":
		tls := map[string]any{"enabled": true, "server_name": sni}
		if fp := q.Get("fp"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if alpn := q.Get("alpn"); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
			tls["insecure"] = true
		}
		return tls
	default:
		return nil
	}
}

// transportBlock builds a sing-box v2ray transport object (ws/grpc/http).
func transportBlock(q url.Values) map[string]any {
	switch q.Get("type") {
	case "ws":
		t := map[string]any{"type": "ws"}
		if p := q.Get("path"); p != "" {
			t["path"] = p
		}
		if h := q.Get("host"); h != "" {
			t["headers"] = map[string]any{"Host": h}
		}
		return t
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": q.Get("serviceName")}
	case "http", "h2":
		t := map[string]any{"type": "http"}
		if p := q.Get("path"); p != "" {
			t["path"] = p
		}
		return t
	default:
		return nil
	}
}

func fromVLESS(rest string) (string, string, int, map[string]any, bool) {
	uuid, host, port, q, tag := parseURLParts(rest)
	if host == "" || uuid == "" {
		return "", "", 0, nil, false
	}
	ob := map[string]any{
		"type": "vless", "tag": nz(tag, "vless-"+host),
		"server": host, "server_port": port, "uuid": uuid,
	}
	if flow := q.Get("flow"); flow != "" {
		ob["flow"] = flow
	}
	if tls := tlsBlock(host, q); tls != nil {
		ob["tls"] = tls
	}
	if tr := transportBlock(q); tr != nil {
		ob["transport"] = tr
	}
	return "vless", host, port, ob, true
}

func fromTrojan(rest string) (string, string, int, map[string]any, bool) {
	pw, host, port, q, tag := parseURLParts(rest)
	if host == "" {
		return "", "", 0, nil, false
	}
	ob := map[string]any{
		"type": "trojan", "tag": nz(tag, "trojan-"+host),
		"server": host, "server_port": port, "password": pw,
	}
	tls := tlsBlock(host, q)
	if tls == nil {
		tls = map[string]any{"enabled": true, "server_name": nz(q.Get("sni"), host)}
	}
	ob["tls"] = tls
	if tr := transportBlock(q); tr != nil {
		ob["transport"] = tr
	}
	return "trojan", host, port, ob, true
}

func fromShadowsocks(rest string) (string, string, int, map[string]any, bool) {
	// forms: ss://base64(method:pass)@host:port#tag  OR  ss://base64(method:pass@host:port)#tag
	rest, frag, _ := strings.Cut(rest, "#")
	tag, _ := url.QueryUnescape(frag)
	rest, _, _ = strings.Cut(rest, "?")

	var method, pass, host string
	var port int
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		method, pass = splitB64Creds(rest[:at])
		host, port = splitHostPort(rest[at+1:])
	} else if dec, ok := tryDecodeB64(rest); ok {
		mp, hp, found := strings.Cut(dec, "@")
		if !found {
			return "", "", 0, nil, false
		}
		method, pass, _ = strings.Cut(mp, ":")
		host, port = splitHostPort(hp)
	}
	if host == "" || method == "" {
		return "", "", 0, nil, false
	}
	ob := map[string]any{
		"type": "shadowsocks", "tag": nz(tag, "ss-"+host),
		"server": host, "server_port": port, "method": method, "password": pass,
	}
	return "shadowsocks", host, port, ob, true
}

func fromVMess(b64 string) (string, string, int, map[string]any, bool) {
	dec, ok := tryDecodeB64(b64)
	if !ok {
		return "", "", 0, nil, false
	}
	var v struct {
		PS, Add, ID, Net, Type, Host, Path, TLS, SNI, SCY string
		Port, Aid                                         json.Number
	}
	if err := json.Unmarshal([]byte(dec), &v); err != nil {
		return "", "", 0, nil, false
	}
	port, _ := strconv.Atoi(v.Port.String())
	aid, _ := strconv.Atoi(v.Aid.String())
	ob := map[string]any{
		"type": "vmess", "tag": nz(v.PS, "vmess-"+v.Add),
		"server": v.Add, "server_port": port, "uuid": v.ID,
		"alter_id": aid, "security": nz(v.SCY, "auto"),
	}
	if v.TLS == "tls" {
		ob["tls"] = map[string]any{"enabled": true, "server_name": nz(v.SNI, v.Host, v.Add)}
	}
	switch v.Net {
	case "ws":
		t := map[string]any{"type": "ws"}
		if v.Path != "" {
			t["path"] = v.Path
		}
		if v.Host != "" {
			t["headers"] = map[string]any{"Host": v.Host}
		}
		ob["transport"] = t
	case "grpc":
		ob["transport"] = map[string]any{"type": "grpc", "service_name": v.Path}
	}
	return "vmess", v.Add, port, ob, v.Add != ""
}

func fromHysteria2(rest string) (string, string, int, map[string]any, bool) {
	pw, host, port, q, tag := parseURLParts(rest)
	if host == "" {
		return "", "", 0, nil, false
	}
	tls := map[string]any{"enabled": true, "server_name": nz(q.Get("sni"), host)}
	if q.Get("insecure") == "1" {
		tls["insecure"] = true
	}
	ob := map[string]any{
		"type": "hysteria2", "tag": nz(tag, "hy2-"+host),
		"server": host, "server_port": port, "password": pw, "tls": tls,
	}
	return "hysteria2", host, port, ob, true
}

func fromTUIC(rest string) (string, string, int, map[string]any, bool) {
	cred, host, port, q, tag := parseURLParts(rest)
	uuid, pass, _ := strings.Cut(cred, ":")
	if host == "" || uuid == "" {
		return "", "", 0, nil, false
	}
	tls := map[string]any{"enabled": true, "server_name": nz(q.Get("sni"), host)}
	if q.Get("allow_insecure") == "1" || q.Get("insecure") == "1" {
		tls["insecure"] = true
	}
	ob := map[string]any{
		"type": "tuic", "tag": nz(tag, "tuic-"+host),
		"server": host, "server_port": port, "uuid": uuid, "password": pass, "tls": tls,
	}
	if cc := q.Get("congestion_control"); cc != "" {
		ob["congestion_control"] = cc
	}
	return "tuic", host, port, ob, true
}

// ---- helpers ----

func nz(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func first(vals ...string) string { return nz(vals...) }

func splitHostPort(s string) (string, int) {
	s = strings.Trim(s, "/")
	host, portStr, _ := strings.Cut(s, ":")
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func splitB64Creds(s string) (method, pass string) {
	if dec, ok := tryDecodeB64(s); ok {
		method, pass, _ = strings.Cut(dec, ":")
		return
	}
	method, pass, _ = strings.Cut(s, ":")
	return
}

func tryDecodeB64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	return "", false
}
