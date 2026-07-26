package cmd

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// The whole point is the case the shell cannot handle itself: it dies without
// running any cleanup, and the gateway has to notice on its own.
func TestWatchParentFiresWhenTheParentDies(t *testing.T) {
	// A short-lived process stands in for the shell.
	cmd := exec.Command("/bin/sh", "-c", "sleep 0.3")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	gone := make(chan struct{})
	stop := watchParent(cmd.Process.Pid, 50*time.Millisecond, func() { close(gone) })
	defer stop()

	_ = cmd.Wait()
	select {
	case <-gone:
	case <-time.After(3 * time.Second):
		t.Fatal("the watcher never noticed the parent exit")
	}
}

func TestWatchParentStaysQuietWhileTheParentLives(t *testing.T) {
	// Our own parent: alive for the duration of the test.
	fired := make(chan struct{}, 1)
	stop := watchParent(os.Getppid(), 20*time.Millisecond, func() { fired <- struct{}{} })
	defer stop()
	select {
	case <-fired:
		t.Fatal("fired while the parent is still running")
	case <-time.After(300 * time.Millisecond):
	}
}

// Guard rails: pid 1 and a pid that is not our parent must not be treated as
// "alive and ours" — a stale pid can be reused by an unrelated process, and
// exiting because some stranger died would kill the gateway for no reason.
func TestParentAliveRejectsInitAndNonParents(t *testing.T) {
	if parentAlive(1) {
		t.Error("pid 1 must not count as our parent")
	}
	if parentAlive(0) || parentAlive(-5) {
		t.Error("non-pids must not count as alive")
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	// A live process that is our *child*, not our parent.
	if parentAlive(cmd.Process.Pid) {
		t.Error("a process that is not our parent must not count")
	}
	if !parentAlive(os.Getppid()) {
		t.Error("our real parent must count as alive")
	}
}
