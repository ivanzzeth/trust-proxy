package cmd

import "golang.org/x/sys/windows"

// Windows has no signals and no getppid, so liveness is asked of the process
// object directly: a handle can be opened for a process that has exited (the
// object outlives it until every handle is closed), and the exit code is what
// distinguishes the two. STILL_ACTIVE (259) means running.
//
// The reparenting check has no Windows equivalent — a process whose parent dies
// is simply orphaned, with the ppid field left pointing at a pid that may have
// been reused. Not emulating it is deliberate: guessing from a recycled pid would
// make the watch kill a healthy gateway.
func parentAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}
