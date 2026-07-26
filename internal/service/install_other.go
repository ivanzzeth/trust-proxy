//go:build !darwin && !linux

package service

import "runtime"

// The launchd path is macOS-only. Windows (a service + UAC) and Linux (systemd +
// polkit or setcap) each need their own privilege model, so they get their own
// implementation rather than a leaky abstraction over this one.

func Install(Config) error { return errUnsupported() }
func Uninstall() error     { return errUnsupported() }

func Status() (bool, bool, string) { return false, false, "" }

func errUnsupported() error {
	return unsupportedError{}
}

type unsupportedError struct{}

func (unsupportedError) Error() string {
	return "system-service install is implemented for macOS (launchd) only; " + runtime.GOOS +
		" needs its own privilege model — run `trust-proxy serve` under your init system for now"
}
