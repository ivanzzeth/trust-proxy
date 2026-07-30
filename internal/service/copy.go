package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// InstallBinary copies src to ManagedBinary and returns the path the plist should
// use. A copy already identical to src is left alone (so re-installing is cheap
// and does not disturb a running daemon's inode).
//
// Copying by content, rather than symlinking, is the point: a symlink would break
// the same way the bundle path does. It also drops the com.apple.quarantine
// attribute — extended attributes are not part of the bytes — which matters for an
// un-notarized build, where a quarantined binary can be killed on exec.
func InstallBinary(src string) (string, error) {
	src, err := filepath.Abs(src)
	if err != nil {
		return "", err
	}
	if src == ManagedBinary {
		return ManagedBinary, nil
	}
	srcSum, err := fileSum(src)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", src, err)
	}
	if dstSum, err := fileSum(ManagedBinary); err == nil && dstSum == srcSum {
		return ManagedBinary, nil
	}
	dir := filepath.Dir(ManagedBinary)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	// MkdirAll respects umask. `install` tightens umask to 0077 so data files
	// stay owner-only, which would leave a freshly created libexec as 0700 —
	// then a non-root `env` / diagnosis cannot even look inside. Force the
	// conventional 0755 regardless of umask (and heal an older 0700 dir).
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", fmt.Errorf("chmod %s: %w", dir, err)
	}
	// Write beside the target and rename: a half-copied gateway that launchd
	// picks up would fail at boot with a truncated binary.
	tmp, err := os.CreateTemp(filepath.Dir(ManagedBinary), ".trust-proxy-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	in, err := os.Open(src)
	if err != nil {
		_ = tmp.Close()
		return "", err
	}
	_, copyErr := io.Copy(tmp, in)
	_ = in.Close()
	if closeErr := tmp.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return "", fmt.Errorf("copy to %s: %w", ManagedBinary, copyErr)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return "", err
	}
	// root:wheel, so an unprivileged process cannot swap out what launchd runs
	// as root. Best-effort: a test running as a normal user cannot chown.
	if os.Geteuid() == 0 {
		if err := os.Chown(tmpName, 0, 0); err != nil {
			return "", fmt.Errorf("chown %s: %w", tmpName, err)
		}
	}
	gotSum, err := fileSum(tmpName)
	if err != nil {
		return "", err
	}
	if gotSum != srcSum {
		return "", fmt.Errorf("copy of %s does not match the source", src)
	}
	if err := os.Rename(tmpName, ManagedBinary); err != nil {
		return "", fmt.Errorf("install %s: %w", ManagedBinary, err)
	}
	return ManagedBinary, nil
}

// writeServiceDefinition writes the plist/unit and forces it world-readable.
//
// The mode passed to WriteFile is a request, not a result: `install` tightens
// umask to 0077 so data files stay owner-only, which lands the definition at
// 0600 — same masking that used to leave libexec at 0700. That one was loud (a
// non-root `env` could not look inside); this one is silent, because the readers
// degrade instead of failing. ProgramFromPlist/ProgramFromUnit return "" on an
// unreadable file, BinaryMissing("") is false, and every check downstream —
// `service status`, `env`'s program_missing, the stale-gateway hint in the
// Makefile — reads that as "nothing to warn about". A service definition is
// public by design; the secrets live in the data directory.
func writeServiceDefinition(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// RemoveManagedBinary deletes the daemon's program, but only when it is the copy
// we made.
//
// The guard is the point: an install can legitimately point at a binary we do not
// own — Homebrew's, or a build tree during development — and uninstall must never
// delete that. Pass the plist's program path (see ProgramFromPlist).
func RemoveManagedBinary(program string) error {
	if program != ManagedBinary {
		return nil // someone else's binary: leave it alone
	}
	if err := os.Remove(ManagedBinary); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DefinitionUnreadable reports that the service is installed but we cannot read
// its definition back — so Program() returned "" for lack of permission, not for
// lack of a service.
//
// Worth its own answer because "" is otherwise indistinguishable from "not
// installed", and every check downstream treats that as fine: BinaryMissing is
// false, the stale-gateway comparison is skipped. Installs before the chmod
// above left the definition at 0600, and this is how a machine in that state
// says so instead of quietly reporting nothing.
func DefinitionUnreadable() bool {
	f := File()
	if f == "" || !Installed() {
		return false
	}
	_, err := os.ReadFile(f)
	return err != nil
}

// BinaryMissing reports whether the plist's program is gone — the brick symptom
// this copy exists to prevent, worth naming in `service status` when it happens.
func BinaryMissing(program string) bool {
	if program == "" {
		return false
	}
	_, err := os.Stat(program)
	return os.IsNotExist(err)
}

// ProgramFromPlist reads back the first ProgramArguments entry, so status can
// show what launchd will actually exec (and notice a stale path).
//
// A minimal scan rather than a plist parser: the file is one we wrote, and the
// alternative is a dependency for reading one string.
func ProgramFromPlist() string {
	data, err := os.ReadFile(PlistPath)
	if err != nil {
		return ""
	}
	text := string(data)
	i := strings.Index(text, "<key>ProgramArguments</key>")
	if i < 0 {
		return ""
	}
	rest := text[i:]
	open := strings.Index(rest, "<string>")
	if open < 0 {
		return ""
	}
	rest = rest[open+len("<string>"):]
	end := strings.Index(rest, "</string>")
	if end < 0 {
		return ""
	}
	return unescapeXML(rest[:end])
}

// firstArg pulls the executable out of a service's command line, which is stored
// as one string and may be quoted.
func firstArg(cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if strings.HasPrefix(cmdline, `"`) {
		if end := strings.Index(cmdline[1:], `"`); end >= 0 {
			return cmdline[1 : 1+end]
		}
	}
	if i := strings.Index(cmdline, " "); i > 0 {
		return cmdline[:i]
	}
	return cmdline
}

func unescapeXML(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`)
	return r.Replace(s)
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
