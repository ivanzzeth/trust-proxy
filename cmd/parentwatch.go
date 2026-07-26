package cmd

import (
	"os"
	"syscall"
	"time"
)

// Parent-death watch.
//
// The desktop shell spawns the gateway as a child. If the shell exits cleanly it
// kills the child — but SIGKILL, a force-quit or a crash gives it no chance, and
// then the data plane keeps running, invisible: ports held, traffic still
// captured, while the user believes the app is gone. Measured, not theorised —
// `kill`ing the shell left the gateway alive.
//
// So the child watches the parent rather than trusting it. A GUI process can die
// in ways it cannot handle; a poll on the parent pid cannot be skipped.

// parentWatchInterval is the poll period. A couple of seconds is invisible to a
// human and costs one signal syscall.
const parentWatchInterval = 2 * time.Second

// watchParent calls onGone once the given pid is no longer alive (or is no
// longer our parent). Returns a stop function.
//
// Signal 0 is the portable liveness probe: it performs the permission checks and
// returns ESRCH for a dead process without delivering anything. Reparenting to
// launchd (pid 1) also counts as gone — that is exactly what happens when the
// shell dies and our real parent disappears.
func watchParent(pid int, interval time.Duration, onGone func()) (stop func()) {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if !parentAlive(pid) {
					onGone()
					return
				}
			}
		}
	}()
	return func() { close(done) }
}

// parentAlive reports whether pid is alive and still our parent.
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
