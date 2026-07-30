package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Install writes the unit and enables it. Needs root: /etc/systemd/system is
// root-owned, and TUN is the reason we are here.
func Install(c Config) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("installing a system service needs root: re-run with sudo")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("no systemctl on this machine: run `trust-proxy serve` under your own init system " +
			"(the flags to use are printed by `trust-proxy service status --json`)")
	}
	// Same rule as macOS: the daemon gets its own copy, so moving or deleting
	// whatever the user installed from cannot leave systemd retrying a missing
	// program at every boot.
	if !c.KeepBinaryPath {
		managed, err := InstallBinary(c.Binary)
		if err != nil {
			return err
		}
		c.Binary = managed
	}
	unit, err := c.Unit()
	if err != nil {
		return err
	}
	// Stop an existing job before replacing its unit, so we never have systemd
	// tracking one unit file while a process from another is still running.
	_ = exec.Command("systemctl", "stop", UnitName).Run()
	if err := writeServiceDefinition(UnitPath, unit); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		_ = os.Remove(UnitPath)
		return fmt.Errorf("systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "enable", "--now", UnitName).CombinedOutput(); err != nil {
		// Leave nothing half-armed: a unit systemd rejected would come back at the
		// next boot and fail there too, out of sight.
		_ = exec.Command("systemctl", "disable", UnitName).Run()
		_ = os.Remove(UnitPath)
		_ = exec.Command("systemctl", "daemon-reload").Run()
		return fmt.Errorf("systemctl enable --now %s: %v: %s", UnitName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Uninstall stops and removes the unit. Deliberately tolerant: this is the escape
// hatch, so it must succeed from a half-installed state.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("removing a system service needs root: re-run with sudo")
	}
	// Read the program before deleting the unit: it is the only record of what
	// this install actually put on the machine.
	program := ProgramFromUnit()
	_ = exec.Command("systemctl", "disable", "--now", UnitName).Run()
	if err := os.Remove(UnitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", UnitPath, err)
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	// Only our own copy — never a binary the user pointed us at.
	if err := RemoveManagedBinary(program); err != nil {
		return fmt.Errorf("remove %s: %w", program, err)
	}
	return nil
}

// Status reports whether the unit exists and what systemd knows about it.
func Status() (installed bool, running bool, detail string) {
	installed = Installed()
	// `is-active` exits non-zero when inactive, which is information, not an
	// error — so the output is what matters, not the exit code.
	out, _ := exec.Command("systemctl", "is-active", UnitName).CombinedOutput()
	state := strings.TrimSpace(string(out))
	running = state == "active"
	if state != "" {
		detail = state
	}
	if !running {
		// When it is not running, why is the useful part. ExecMainStatus is the
		// exit code of the last run: 0 with inactive means "stopped on purpose",
		// non-zero means it is failing and systemd is retrying.
		if out, err := exec.Command("systemctl", "show", "-p", "ExecMainStatus", "--value", UnitName).CombinedOutput(); err == nil {
			if code := strings.TrimSpace(string(out)); code != "" && code != "0" {
				detail = state + ", last exit code = " + code
			}
		}
	}
	return installed, running, detail
}
