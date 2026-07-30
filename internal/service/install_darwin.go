//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Install writes the plist and bootstraps the job. Requires root — launchd
// refuses /Library/LaunchDaemons otherwise, and TUN is the reason we are here.
func Install(c Config) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("installing a system service needs root: re-run with sudo")
	}
	// Give the daemon its own copy of the binary unless the caller insists on the
	// path it passed. Pointing launchd inside an .app is the brick: trash the app
	// and KeepAlive retries a missing program forever, from every boot onward.
	if !c.KeepBinaryPath {
		managed, err := InstallBinary(c.Binary)
		if err != nil {
			return err
		}
		c.Binary = managed
	}
	plist, err := c.Plist()
	if err != nil {
		return err
	}
	// Replace an existing job rather than stacking two: bootout first, ignoring
	// "not loaded" so a half-installed state still converges.
	//
	// bootout returns as soon as it has *signalled* the job. launchd then spends
	// a beat in SIGTERMed → EXITED → PETRIFIED before the label is free again.
	// An immediate bootstrap fails with "37: Operation already in progress"; we
	// used to delete the plist on that failure and leave the machine with no
	// gateway at all — which is exactly what the desktop Update button did on a
	// live install. Wait for the label to clear, then retry on that specific race.
	_ = exec.Command("launchctl", "bootout", "system/"+Label).Run()
	waitLaunchdJobGone(10 * time.Second)
	if err := writeServiceDefinition(PlistPath, plist); err != nil {
		return err
	}
	if err := os.Chown(PlistPath, 0, 0); err != nil {
		return fmt.Errorf("chown %s: %w", PlistPath, err)
	}
	if err := bootstrapLaunchd(PlistPath); err != nil {
		// Leave nothing half-armed: a plist on disk that launchd rejected would
		// come back at the next boot and fail there too, out of sight.
		_ = os.Remove(PlistPath)
		return err
	}
	return nil
}

// waitLaunchdJobGone polls until launchctl no longer knows the label, or the
// deadline passes. Soft on timeout: bootstrapLaunchd still retries error 37.
func waitLaunchdJobGone(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !launchdJobLoaded() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func launchdJobLoaded() bool {
	return exec.Command("launchctl", "print", "system/"+Label).Run() == nil
}

// bootstrapLaunchd loads the plist, retrying the bootout-settling race.
func bootstrapLaunchd(plistPath string) error {
	var lastOut []byte
	var lastErr error
	for attempt := 0; attempt < 25; attempt++ {
		if attempt > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		lastOut, lastErr = exec.Command("launchctl", "bootstrap", "system", plistPath).CombinedOutput()
		if lastErr == nil {
			return nil
		}
		if !bootstrapInProgress(string(lastOut)) {
			break
		}
	}
	return fmt.Errorf("launchctl bootstrap: %v: %s", lastErr, strings.TrimSpace(string(lastOut)))
}

// bootstrapInProgress is the race we wait out: bootout has signalled the old
// job but launchd has not finished removing the label yet.
func bootstrapInProgress(out string) bool {
	return strings.Contains(out, "Operation already in progress") ||
		strings.Contains(out, "37:")
}

// Uninstall stops the job and removes the plist. Deliberately tolerant: this is
// the escape hatch, so it must succeed even from a half-installed state.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("removing a system service needs root: re-run with sudo")
	}
	// Read the program before deleting the plist: it is the only record of what
	// this install actually put on the machine.
	program := ProgramFromPlist()
	_ = exec.Command("launchctl", "bootout", "system/"+Label).Run()
	waitLaunchdJobGone(10 * time.Second)
	if err := os.Remove(PlistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", PlistPath, err)
	}
	// Only our own copy — never a binary the user pointed us at.
	if err := RemoveManagedBinary(program); err != nil {
		return fmt.Errorf("remove %s: %w", program, err)
	}
	return nil
}

// Status reports whether the plist exists and what launchd knows about the job.
func Status() (installed bool, running bool, detail string) {
	installed = Installed()
	out, err := exec.Command("launchctl", "print", "system/"+Label).CombinedOutput()
	if err != nil {
		return installed, false, ""
	}
	text := string(out)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pid = ") {
			running = true
			detail = line
		}
		if strings.HasPrefix(line, "last exit code = ") && detail == "" {
			detail = line
		}
	}
	return installed, running, detail
}
