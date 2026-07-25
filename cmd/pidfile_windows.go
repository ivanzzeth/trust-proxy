//go:build windows

package cmd

// checkPid is a portability stub: --daemon is unsupported on Windows (see
// daemon_windows.go), so the double-start guard never applies there, and
// `proxy stop` keeps its pre-existing behavior of always attempting the
// signal rather than trying to pre-verify liveness/identity.
func checkPid(pid int) (alive, confirmedOther bool) { return true, false }
