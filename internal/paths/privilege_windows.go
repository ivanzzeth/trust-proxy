package paths

import (
	"golang.org/x/sys/windows"
)

// Privileged reports whether this process is running elevated.
//
// "Is the user an administrator" is the wrong question on Windows: with UAC on, an
// admin's normal process is *not* elevated, and everything a gateway needs
// (registering a service, creating a wintun adapter) fails anyway. What matters is
// whether this token is elevated right now — and that is what IsMember answers,
// because a non-elevated admin carries the Administrators group as deny-only.
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

// CanTUN reports whether TUN mode has a chance of working here.
//
// Elevation is the only requirement: wintun.dll is embedded in the binary (see
// sing-tun's internal/wintun, which memory-loads it) so there is nothing to
// install or find on disk. An earlier version of this checked for wintun.dll next
// to the executable and would have reported "TUN is impossible" on every machine
// where it works — being wrong in that direction hides a working setup, which is
// worse than one clear error message.
func CanTUN() bool { return Privileged() }
