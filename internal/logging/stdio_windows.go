//go:build windows

package logging

import (
	"os"

	"golang.org/x/sys/windows"
)

// redirectStdio points the process's stdout and stderr at f. SetStdHandle is the
// Windows equivalent of dup2 for this purpose; os.Stdout/os.Stderr keep their own
// handles, so they are replaced as well.
func redirectStdio(f *os.File) error {
	h := windows.Handle(f.Fd())
	if err := windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, h); err != nil {
		return err
	}
	if err := windows.SetStdHandle(windows.STD_ERROR_HANDLE, h); err != nil {
		return err
	}
	os.Stdout = f
	os.Stderr = f
	return nil
}
