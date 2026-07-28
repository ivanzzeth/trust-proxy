//go:build !windows

package credentials

import "syscall"

// noFollow refuses to open through a symlink.
//
// This matters because `install` runs as root and writes into the home directory
// of the account named by --claim-for, which is arbitrary and untrusted: without
// it, a link left at credentials.json.tmp has root truncate and write whatever it
// points at.
const noFollow = syscall.O_NOFOLLOW
