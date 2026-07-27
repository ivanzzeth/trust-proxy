package cmd

import (
	"io/fs"
	"os"
)

// dataDirMode is the permission the data directory gets: owner only.
//
// It used to be 0755, and the files inside it were mostly 0644, so on the only
// supported deployment — machine-wide, root-owned — every local account could
// read the whole policy plus every exit credential. The API is careful about
// exactly this: subscription URLs and node outbounds are redacted before they
// reach a browser, and even an admin cannot read a stored proxy password back.
// None of that mattered while the file was world-readable.
//
// The directory is the cheaper half of the fix: at 0700 an unprivileged process
// cannot even list the names, whatever the individual files say. The files are
// tightened as well, because a directory permission is the one thing a copied or
// bind-mounted data directory does not bring with it.
const dataDirMode fs.FileMode = 0o700

// tightenDataDir narrows an existing data directory that was created by an older
// version.
//
// MkdirAll leaves an existing directory's mode alone, so without this every
// machine installed before the change keeps 0755 forever — and the machines that
// have been running longest are the ones with the most in there. Best-effort: a
// gateway that cannot chmod its own directory should still come up and enforce
// policy, so this reports rather than refuses.
func tightenDataDir(dir string) (changed bool) {
	fi, err := os.Stat(dir)
	if err != nil {
		return false
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return false
	}
	return os.Chmod(dir, dataDirMode) == nil
}

// tightenLogFile narrows the daemon log, which neither our umask nor an explicit
// mode can reach.
//
// The service does not run `serve --daemon`: systemd redirects stdout/stderr with
// StandardOutput=append: and launchd with StandardOutPath, so the *service manager*
// creates the file, at 0644, and neither offers a way to ask for anything else. It
// matters because the log is not boring — it carries the one-time bootstrap claim
// code verbatim, every destination every account reaches, and sniffed SNI.
//
// Best-effort and idempotent: run at startup, after the manager has created the
// file (or before, in which case there is nothing to do and the next start gets it).
func tightenLogFile(path string) {
	if path == "" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Mode().Perm()&0o077 == 0 {
		return
	}
	_ = os.Chmod(path, 0o600)
}
