//go:build !windows

package service

import (
	"os"
	"runtime"
)

// File is the path of the service definition on this OS: a launchd plist, a
// systemd unit, or empty where we have no implementation. Callers (the CLI, the
// desktop shell) should print this rather than assuming a plist.
//
// Windows has no such file — the SCM registration *is* the installation — so it
// defines its own File/Program/Installed in install_windows.go.
func File() string {
	switch runtime.GOOS {
	case "darwin":
		return PlistPath
	case "linux":
		return UnitPath
	default:
		return ""
	}
}

// Program is what the installed service will actually exec, read back from the
// service definition — so status can notice a stale path.
func Program() string {
	switch runtime.GOOS {
	case "darwin":
		return ProgramFromPlist()
	case "linux":
		return ProgramFromUnit()
	default:
		return ""
	}
}

// Installed reports whether our service definition is present.
func Installed() bool {
	f := File()
	if f == "" {
		return false
	}
	_, err := os.Stat(f)
	return err == nil
}
