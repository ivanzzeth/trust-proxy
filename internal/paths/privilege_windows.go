package paths

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Privileged reports whether this process is running elevated.
//
// "Is the user an administrator" is the wrong question on Windows: with UAC on, an
// admin's normal process is *not* elevated, and everything a gateway needs
// (installing a service, creating a wintun adapter) fails anyway. What matters is
// whether this token is elevated right now.
func Privileged() bool {
	var sid *windows.SID
	// S-1-5-32-544 = BUILTIN\Administrators.
	if err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid); err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	token := windows.Token(0) // the current process token
	member, err := token.IsMember(sid)
	return err == nil && member
}

// CanTUN reports whether TUN mode has a chance of working: it needs elevation and
// wintun.dll, which we ship next to the binary. Saying so up front is the
// difference between one clear message and a failed switch on a machine whose
// network is being reconfigured.
func CanTUN() bool {
	if !Privileged() {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	for _, dir := range []string{filepath.Dir(exe), filepath.Join(SystemData(), "bin")} {
		if _, err := os.Stat(filepath.Join(dir, "wintun.dll")); err == nil {
			return true
		}
	}
	// It may still be resolvable from the system search path; do not claim it
	// cannot work.
	_, err = os.Stat(filepath.Join(os.Getenv("SystemRoot"), "System32", "wintun.dll"))
	return err == nil
}
