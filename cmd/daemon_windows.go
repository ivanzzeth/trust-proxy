//go:build windows

package cmd

import "errors"

// daemonize is unsupported on Windows; run as a Windows service instead.
func daemonize(logPath, pidPath string) error {
	return errors.New("--daemon is not supported on Windows; run it as a Windows service or use a process manager")
}
