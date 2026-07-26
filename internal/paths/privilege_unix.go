//go:build !windows

package paths

import (
	"os"
	"runtime"
)

// Privileged reports whether this process can do the things TUN and a
// system-wide service need (create a tun device, write /Library or /var/lib,
// load a launchd/systemd unit).
func Privileged() bool { return os.Geteuid() == 0 }

// CanTUN reports whether asking for TUN mode has a chance of working, so the UI
// can say "this needs elevation" before a doomed switch instead of after a
// failure that on some stacks leaves the network half-configured.
//
// Linux can also be granted CAP_NET_ADMIN on the binary, which is a legitimate
// non-root way to run TUN — so an unprivileged Linux process is "maybe", not
// "no". Being wrong in the optimistic direction costs one clear error message;
// being wrong the other way hides a working setup.
func CanTUN() bool { return Privileged() || runtime.GOOS == "linux" }
