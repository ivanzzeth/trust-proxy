// Package shellquote renders a value as one safe shell word.
//
// It exists because two surfaces print commands for an operator to paste — the
// exit-node deploy script (internal/proxygen) and the subscription rebuild hint
// (cmd/sub.go) — and both feed them user-controlled strings: node titles,
// subscription URLs full of ? and &, base64 keys with $ and backticks. Two
// copies of this would be two things to get subtly wrong.
package shellquote

import "strings"

// Quote makes s safe as a single shell word. Single quotes disable every
// expansion; an embedded quote is closed, escaped and reopened — the usual POSIX
// trick. Words made only of characters no shell treats specially are returned
// as-is, so ordinary output stays readable.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r == '.' || r == '-' || r == '_' || r == '/' || r == ':' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
