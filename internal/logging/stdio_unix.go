//go:build !windows

package logging

import (
	"os"

	"golang.org/x/sys/unix"
)

// redirectStdio points the process's stdout and stderr at f. dup2 keeps fd
// numbers 1 and 2 valid, so os.Stdout / os.Stderr — and everything already
// holding them, including sing-box's logger — write to the new file with no
// further plumbing.
func redirectStdio(f *os.File) error {
	fd := int(f.Fd())
	if err := unix.Dup2(fd, int(os.Stdout.Fd())); err != nil {
		return err
	}
	return unix.Dup2(fd, int(os.Stderr.Fd()))
}
