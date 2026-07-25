package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestReadPidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.pid")
	if err := os.WriteFile(path, []byte("12345\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pid, err := readPidFile(path)
	if err != nil || pid != 12345 {
		t.Fatalf("pid=%d err=%v", pid, err)
	}

	if err := os.WriteFile(path, []byte("not-a-pid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPidFile(path); err == nil {
		t.Fatal("expected error on non-numeric pid file")
	}

	if _, err := readPidFile(filepath.Join(t.TempDir(), "missing.pid")); err == nil {
		t.Fatal("expected error on missing pid file")
	}
}

func TestCheckPidDeadProcess(t *testing.T) {
	// Spawn and immediately wait-reap a process to get a pid that is
	// guaranteed not alive, without guessing at unused pids on the host.
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Skip("no `true` binary on this system")
	}
	pid := cmd.ProcessState.Pid()
	alive, confirmedOther := checkPid(pid)
	if alive {
		t.Fatalf("expected reaped pid %d to be reported dead", pid)
	}
	if confirmedOther {
		t.Fatalf("dead pid should not also claim confirmedOther")
	}
}

func TestCheckPidSelf(t *testing.T) {
	// The test process itself is always alive; go test's own binary name
	// won't match "trust-proxy", so confirmedOther should be true here (or,
	// if `ps` is unavailable/inconclusive on this system, false — either is
	// acceptable, this just exercises the live-process path end-to-end).
	alive, _ := checkPid(os.Getpid())
	if !alive {
		t.Fatal("expected the current process to be reported alive")
	}
}
