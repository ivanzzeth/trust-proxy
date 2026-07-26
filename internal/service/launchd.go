// Package service installs the gateway as a system service, so TUN capture has
// the privileges it needs without a human typing sudo every time.
//
// Why a system service rather than the desktop shell asking for root: the shell
// is a webview, and a GUI app that runs the data plane as its own child dies with
// the UI — closing a window would drop everyone's network policy. launchd owns
// the daemon instead; the shell only talks to its API.
//
// Anti-brick rules, same spirit as the mode dead-man's switch:
//   - one command removes it (`service uninstall`), and it works even if the
//     binary that installed it is gone (the plist is the only state);
//   - the service starts in whatever capture mode is configured, and installing
//     it never turns TUN on by itself;
//   - the label is ours alone, so nothing else on the machine is touched.
package service

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ivanzzeth/trust-proxy/internal/paths"
)

// Label is the launchd job label. Also the plist basename.
const Label = "io.trust-proxy.gateway"

// PlistPath is where a system-wide (root) LaunchDaemon lives.
//
// A var, not a const, only so tests can redirect it away from a root-owned path.
var PlistPath = "/Library/LaunchDaemons/" + Label + ".plist"

// ManagedBinary is where install copies the gateway to.
//
// Never point a LaunchDaemon at a binary inside an .app bundle: moving the app to
// the Trash, or an update replacing the bundle, leaves the plist pointing at
// nothing — and KeepAlive then retries a doomed exec forever, at boot, with the
// failure visible only in a log nobody opens. The daemon gets its own copy, and
// the desktop app becomes just a window again.
//
// /usr/local/libexec is the conventional place for a program that is run by
// something else rather than typed by a human.
//
// A var, not a const, only so tests can redirect it away from a root-owned path.
var ManagedBinary = paths.ManagedBinary()

// Config describes the daemon to install.
type Config struct {
	Binary     string // absolute path to the trust-proxy binary
	ConfigPath string // sing-box config (-c)
	DataDir    string // --data
	APIAddr    string // --api-addr
	Mode       string // --mode (manual | system | tun); empty = leave the default
	LogPath    string // stdout/stderr destination

	// KeepBinaryPath runs Binary where it stands instead of copying it to
	// ManagedBinary. For a package-managed install (Homebrew, a distro package)
	// whose path is already stable; not for anything inside an .app.
	KeepBinaryPath bool
}

// Plist renders the LaunchDaemon property list.
//
// KeepAlive restarts the daemon if it dies — a gateway that stays down is a
// gateway that stops enforcing policy. RunAtLoad makes it come up at boot, which
// is the whole point of installing it: the desktop shell should find a running
// gateway rather than start one.
func (c Config) Plist() (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	args := []string{c.Binary, "serve", "-c", c.ConfigPath, "--data", c.DataDir, "--api-addr", c.APIAddr}
	if c.Mode != "" {
		args = append(args, "--mode", c.Mode)
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	b.WriteString("\t<key>Label</key>\n\t<string>" + xmlEscape(Label) + "</string>\n")
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, a := range args {
		b.WriteString("\t\t<string>" + xmlEscape(a) + "</string>\n")
	}
	b.WriteString("\t</array>\n")
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	b.WriteString("\t<key>KeepAlive</key>\n\t<true/>\n")
	b.WriteString("\t<key>ProcessType</key>\n\t<string>Interactive</string>\n")
	b.WriteString("\t<key>StandardOutPath</key>\n\t<string>" + xmlEscape(c.LogPath) + "</string>\n")
	b.WriteString("\t<key>StandardErrorPath</key>\n\t<string>" + xmlEscape(c.LogPath) + "</string>\n")
	b.WriteString("\t<key>WorkingDirectory</key>\n\t<string>" + xmlEscape(filepath.Dir(c.Binary)) + "</string>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String(), nil
}

// validate refuses a config that would produce a daemon nobody can fix: launchd
// resolves nothing for us, so every path must already be absolute.
func (c Config) validate() error {
	for _, f := range []struct{ name, val string }{
		{"binary", c.Binary}, {"config", c.ConfigPath}, {"data dir", c.DataDir}, {"log path", c.LogPath},
	} {
		if f.val == "" {
			return fmt.Errorf("%s is required", f.name)
		}
		if !filepath.IsAbs(f.val) {
			return fmt.Errorf("%s must be an absolute path (launchd has no working directory to resolve %q)", f.name, f.val)
		}
	}
	if c.APIAddr == "" {
		return fmt.Errorf("api address is required")
	}
	switch c.Mode {
	case "", "manual", "system", "tun":
	default:
		return fmt.Errorf("mode must be manual, system or tun (got %q)", c.Mode)
	}
	return nil
}

// File is the path of the service definition on this OS: a launchd plist, a
// systemd unit, or empty where we have no implementation. Callers (the CLI, the
// desktop shell) should print this rather than assuming a plist.
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

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
