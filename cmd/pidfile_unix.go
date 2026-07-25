//go:build !windows

package cmd

import (
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// checkPid reports whether pid refers to a live process (signal 0 checks
// existence/permission without actually signaling), and whether we have
// positive evidence it is a DIFFERENT (non-trust-proxy) process — e.g. the
// pid was reused after the original daemon died. When identity can't be
// determined (ps unavailable/failed), confirmedOther is false: callers
// shouldn't refuse an action just because they couldn't positively confirm.
func checkPid(pid int) (alive, confirmedOther bool) {
	if syscall.Kill(pid, 0) != nil {
		return false, false
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return true, false
	}
	return true, !strings.Contains(strings.ToLower(string(out)), "trust-proxy")
}
