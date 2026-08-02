package proxygroups

import (
	"net"
	"strings"
)

// Airport placeholder used by some providers for quota / redirect "nodes".
// Connecting to it never yields a usable exit — it only exists so the
// subscription list can carry metadata lines that look like proxies.
const placeholderJunkServer = "123.123.213.213"

// IsJunkNode reports whether a subscription entry is an airport info /
// redirect line that must never join Auto (or any urltest). Returns a short
// reason suitable for API/CLI when junk is true.
//
// Fingerprints are tag + server, not "no country flag" — unflagged real nodes
// exist and must stay selectable.
func IsJunkNode(tag, server string, port int) (bool, string) {
	low := strings.ToLower(strings.TrimSpace(tag))
	if low == "" && strings.TrimSpace(server) == "" {
		return false, ""
	}
	for _, needle := range junkTagNeedles {
		if strings.Contains(low, needle) {
			return true, "tag:" + needle
		}
	}
	// Quota lines like "35.77 GB | 300 GB" — looksLikeDataSize alone is too
	// broad (a node could legitimately mention GB); require the pipe that
	// airports use for remaining|total.
	if looksLikeDataSize(low) && strings.Contains(tag, "|") {
		return true, "tag:quota"
	}
	host := junkHost(server)
	if host == placeholderJunkServer {
		return true, "server:placeholder"
	}
	_ = port // reserved: port 53+placeholder is covered by server match
	return false, ""
}

var junkTagNeedles = []string{
	"跳转域名",
	"请勿连接",
	"traffic reset",
	"expire date",
	"剩余流量",
	"套餐到期",
	"距离下次重置",
}

func junkHost(server string) string {
	host := strings.TrimSpace(server)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}
