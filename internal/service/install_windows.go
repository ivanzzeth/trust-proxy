package service

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/ivanzzeth/trust-proxy/internal/paths"
)

// Windows Service Control Manager path. Same Config and the same anti-brick rules
// as launchd and systemd: the daemon runs its own copy of the binary, one command
// removes it, and installing never turns capture on by itself.
//
// The difference from the Unix paths is that a Windows service is not just "a
// process the OS starts" — it must talk the SCM protocol (report Running, handle
// Stop) or the SCM kills it after its start timeout. That is what `serve
// --windows-service` is for; see RunAsService.

// WindowsServiceName is the SCM service name; WindowsDisplayName is what appears
// in services.msc.
const (
	WindowsServiceName = "trust-proxy"
	WindowsDisplayName = "Trust Proxy Gateway"
)

// Install registers the service with the SCM and starts it. Needs an elevated
// process — the SCM refuses CreateService otherwise.
func Install(c Config) error {
	if !elevated() {
		return fmt.Errorf("installing a system service needs an elevated process: " +
			"run this from an Administrator prompt (or let the desktop app ask)")
	}
	if !c.KeepBinaryPath {
		managed, err := InstallBinary(c.Binary)
		if err != nil {
			return err
		}
		c.Binary = managed
	}
	args, err := c.serviceArgs()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager: %w", err)
	}
	defer m.Disconnect()

	// Replace rather than stack: an existing service with a stale binary path is
	// exactly the state this is here to fix.
	if existing, err := m.OpenService(WindowsServiceName); err == nil {
		_ = stopAndWait(existing)
		delErr := existing.Delete()
		_ = existing.Close()
		if delErr != nil {
			return fmt.Errorf("replace the existing service: %w", delErr)
		}
		// The SCM keeps a deleted service until its last handle closes; a
		// CreateService immediately after can fail with "marked for deletion".
		for i := 0; i < 20; i++ {
			s, err := m.OpenService(WindowsServiceName)
			if err != nil {
				break
			}
			_ = s.Close()
			time.Sleep(250 * time.Millisecond)
		}
	}

	s, err := m.CreateService(WindowsServiceName, c.Binary, mgr.Config{
		DisplayName: WindowsDisplayName,
		Description: "Egress control, detection and anomaly gateway (trust-proxy).",
		// Automatic, because a gateway that only runs when someone logs in is not
		// enforcing policy at boot — the whole reason to install a service.
		StartType: mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return fmt.Errorf("create the service: %w", err)
	}
	defer s.Close()

	// Restart on failure, the SCM's equivalent of KeepAlive / Restart=always.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 3 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 3 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
	}, 86400); err != nil {
		// Not fatal: the service works, it just would not come back by itself.
		// Saying so beats silently installing something less durable than it looks.
		return fmt.Errorf("service installed, but its restart-on-failure policy could not be set: %w", err)
	}
	if err := s.Start(); err != nil {
		// Leave nothing half-armed, same as the other two platforms.
		_ = s.Delete()
		return fmt.Errorf("start the service: %w", err)
	}
	return nil
}

// Uninstall stops and deletes the service. Tolerant by design: this is the escape
// hatch, so it must work from a half-installed state.
func Uninstall() error {
	if !elevated() {
		return fmt.Errorf("removing a system service needs an elevated process: " +
			"run this from an Administrator prompt")
	}
	program := Program()
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(WindowsServiceName)
	if err == nil {
		_ = stopAndWait(s)
		delErr := s.Delete()
		_ = s.Close()
		if delErr != nil {
			return fmt.Errorf("delete the service: %w", delErr)
		}
	}
	if err := RemoveManagedBinary(program); err != nil {
		return fmt.Errorf("remove %s: %w", program, err)
	}
	return nil
}

// Status reports whether the service is registered and running.
func Status() (installed bool, running bool, detail string) {
	m, err := mgr.Connect()
	if err != nil {
		return false, false, ""
	}
	defer m.Disconnect()
	s, err := m.OpenService(WindowsServiceName)
	if err != nil {
		return false, false, ""
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return true, false, ""
	}
	switch st.State {
	case svc.Running:
		return true, true, fmt.Sprintf("pid = %d", st.ProcessId)
	case svc.StartPending:
		return true, false, "starting"
	case svc.StopPending:
		return true, false, "stopping"
	default:
		if st.Win32ExitCode != 0 {
			return true, false, fmt.Sprintf("stopped, last exit code = %d", st.Win32ExitCode)
		}
		return true, false, "stopped"
	}
}

// Installed reports whether the service is registered with the SCM.
//
// Unlike the Unix paths there is no file to stat — the registry entry *is* the
// installation, and reading it through the SCM is the only honest answer.
func Installed() bool {
	installed, _, _ := Status()
	return installed
}

// File is what `service status` shows as "where the service lives". On Windows
// that is the SCM, not a path.
func File() string { return `SCM\` + WindowsServiceName }

// Program is the binary the SCM will run, read back from the service config so a
// stale path is visible.
func Program() string {
	m, err := mgr.Connect()
	if err != nil {
		return ""
	}
	defer m.Disconnect()
	s, err := m.OpenService(WindowsServiceName)
	if err != nil {
		return ""
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return ""
	}
	return firstArg(cfg.BinaryPathName)
}

func stopAndWait(s *mgr.Service) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("service did not stop within 20s")
		}
		time.Sleep(300 * time.Millisecond)
		st, err = s.Query()
		if err != nil {
			return err
		}
	}
	return nil
}

// elevated asks the process token, not the filesystem: mgr.Connect() succeeds
// read-only for a non-elevated caller, so it cannot be the test, and probing by
// writing somewhere privileged leaves litter on a machine we are about to
// configure.
func elevated() bool { return paths.Privileged() }
