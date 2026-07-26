//go:build !windows

package cmd

import (
	"fmt"
	"runtime"
)

// runWindowsService exists on every platform so serve.go needs no build tags; it
// is only reachable via --windows-service, which nothing but the Windows SCM
// passes.
func runWindowsService(func() error) error {
	return fmt.Errorf("--windows-service is a Windows-only flag (this is %s)", runtime.GOOS)
}
