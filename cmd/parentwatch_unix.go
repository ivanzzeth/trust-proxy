//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

// Signal 0 is the portable liveness probe: it performs the permission checks and
// returns ESRCH for a dead process without delivering anything. Reparenting to
// init (pid 1) also counts as gone — that is exactly what happens when the shell
// dies and our real parent disappears.
func parentAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	if os.Getppid() != pid {
		// We were reparented: whoever spawned us is gone.
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
