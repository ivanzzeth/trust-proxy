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
	"path/filepath"
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
	LogPath    string // stdout/stderr destination
	// ConsoleDir is an absolute path to a built dashboard, for a binary that does
	// not carry one. Empty means the binary has the UI embedded (or the operator
	// accepts an API-only gateway) — see Config.serveFlags.
	ConsoleDir string

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
	args := append([]string{c.Binary}, c.serveFlags()...)
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

// validate refuses a config that would produce a daemon nobody can fix: no
// service manager — launchd, systemd or the SCM — resolves a relative path for
// us, and a daemon started at boot has no useful working directory to resolve it
// against either.
func (c Config) validate() error {
	for _, f := range []struct{ name, val string }{
		{"binary", c.Binary}, {"config", c.ConfigPath}, {"data dir", c.DataDir}, {"log path", c.LogPath},
	} {
		if f.val == "" {
			return fmt.Errorf("%s is required", f.name)
		}
		if !filepath.IsAbs(f.val) {
			return fmt.Errorf("%s must be an absolute path (a service manager has no working directory to resolve %q against)", f.name, f.val)
		}
	}
	if c.APIAddr == "" {
		return fmt.Errorf("api address is required")
	}
	return nil
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// serveFlags is the one place the daemon's command line is defined, so launchd,
// systemd and the SCM cannot drift apart.
//
// --console matters more than it looks: its default is a *relative* path, which
// resolves to nothing for a daemon whose working directory is /usr/local/libexec.
// Without an absolute one (or an embedded UI) the install succeeds and the console
// then answers "dashboard not built".
func (c Config) serveFlags() []string {
	args := []string{"serve", "-c", c.ConfigPath, "--data", c.DataDir, "--api-addr", c.APIAddr}
	if c.ConsoleDir != "" {
		args = append(args, "--console", c.ConsoleDir)
	}
	// No --mode. It used to be here, and being here was the bug: the service
	// definition was the only durable record of the capture mode, so switching to
	// TUN from the console lasted until the next restart, and a bare re-install —
	// which is the documented upgrade path — rewrote this list without the argument
	// and silently turned capture off on a machine that had it on. The mode is a
	// policy axis and now lives in a store like the other six; `install --mode`
	// seeds that store instead of pinning an argument here.
	return args
}

// serviceArgs is the argument list the SCM passes to the binary: the same `serve`
// flags as everywhere else, plus --windows-service so the process knows to talk
// the SCM protocol instead of running as a plain foreground gateway.
func (c Config) serviceArgs() ([]string, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	args := append(c.serveFlags(), "--log", c.LogPath)
	// The SCM starts the process itself, so it has to speak the SCM protocol.
	return append(args[:1:1], append([]string{"--windows-service"}, args[1:]...)...), nil
}
