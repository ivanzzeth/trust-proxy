package cmd

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Finding the process that holds a TCP port, when it will not tell us itself.
//
// `install --takeover` has to stop whatever is on the API port. Three ways to
// learn which process that is, in decreasing order of reliability:
//
//  1. **ask it** — /api/health reports its own pid to loopback callers. Exact,
//     needs no privileges beyond reaching the port, and cannot be stale.
//  2. **a pid file** — only exists for `serve --daemon`, and can be left behind by
//     a process that is long gone.
//  3. **ask the OS** — this file. Needed for gateways too old to report a pid, and
//     for one started in a terminal, which never writes a pid file at all.
//
// The OS has no portable API for "who owns this port", so this shells out. That
// is worth it here: the alternative is telling somebody to go find the process
// themselves, in a window whose entire purpose is that they should not have to.
//
// Every helper is best-effort — a missing tool, a truncated output or an
// unparsable line yields 0, and the caller falls through to the next source or to
// an error that says what it could not do.

// portOwnerPID returns the pid listening on a loopback TCP port, or 0.
//
// Note it needs to be able to *see* the socket: an unprivileged process cannot
// see one owned by root. That is fine here, because `install` is root by the time
// it asks.
func portOwnerPID(addr string) int {
	port := portOf(addr)
	if port == "" {
		return 0
	}
	switch runtime.GOOS {
	case "windows":
		return pidFromNetstat(runCmd("netstat", "-ano", "-p", "tcp"), port)
	default:
		// lsof is present on macOS by default and usual on Linux; ss ships with
		// iproute2, which a machine running a network gateway almost certainly has.
		// Trying both costs one failed exec on the systems that lack one.
		if pid := firstPID(runCmd("lsof", "-nP", "-iTCP:"+port, "-sTCP:LISTEN", "-t")); pid != 0 {
			return pid
		}
		return pidFromSS(runCmd("ss", "-H", "-ltnp", "sport = :"+port))
	}
}

func runCmd(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}

// portOf pulls the port out of a listen address ("127.0.0.1:21585", ":21585").
func portOf(addr string) string {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return ""
	}
	port := strings.TrimSpace(addr[i+1:])
	if _, err := strconv.Atoi(port); err != nil {
		return ""
	}
	return port
}

// firstPID reads `lsof -t` output: one pid per line.
func firstPID(out string) int {
	for _, line := range strings.Split(out, "\n") {
		if n, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// pidFromSS digs the pid out of ss's users:(("name",pid=123,fd=9)) field.
func pidFromSS(out string) int {
	const marker = "pid="
	for {
		i := strings.Index(out, marker)
		if i < 0 {
			return 0
		}
		rest := out[i+len(marker):]
		end := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
		if end < 0 {
			end = len(rest)
		}
		if n, err := strconv.Atoi(rest[:end]); err == nil && n > 0 {
			return n
		}
		out = rest
	}
}

// pidFromNetstat reads Windows netstat -ano: the pid is the last column of a
// LISTENING row whose local address ends in :port.
//
// Matching the *end* of the address rather than searching the line for the port
// number: the remote address and the pid are on the same row, and a port that
// happens to appear in either would otherwise match.
func pidFromNetstat(out, port string) int {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.EqualFold(f[3], "LISTENING") {
			continue
		}
		if !strings.HasSuffix(f[1], ":"+port) {
			continue
		}
		if n, err := strconv.Atoi(f[4]); err == nil && n > 0 {
			return n
		}
	}
	return 0
}
