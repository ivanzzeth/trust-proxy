//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// daemonize re-executes the current command detached from the controlling
// terminal (setsid), so it survives an SSH logout. The child is marked via
// TP_DAEMON=1 so it runs the server instead of re-daemonizing. Output goes to
// logPath; the child pid is written to pidPath.
func daemonize(logPath, pidPath string) error {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open log %s: %w", logPath, err)
	}
	defer logf.Close()

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "TP_DAEMON=1")
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	if pidPath != "" {
		_ = os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o644)
	}
	fmt.Printf("daemon started (pid %d); logs -> %s, pid -> %s\n", cmd.Process.Pid, logPath, pidPath)
	fmt.Printf("stop it with: trust-proxy proxy stop --pid %s\n", pidPath)
	return nil
}
