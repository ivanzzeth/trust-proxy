package cmd

import (
	"fmt"

	"golang.org/x/sys/windows/svc"

	"github.com/ivanzzeth/trust-proxy/internal/logging"
)

// Windows Service Control Manager plumbing.
//
// A service is not simply a process the SCM launches: it has to connect back,
// report StartPending → Running, and answer Stop/Shutdown. A gateway that just
// runs its main loop is killed when the SCM's start timeout expires (30s by
// default) — it looks like "the service will not start" with nothing in any log,
// which is why this is here rather than being left to `serve` alone.

// runWindowsService runs fn under the SCM.
func runWindowsService(fn func() error) error {
	interactive, err := svc.IsAnInteractiveSession()
	if err != nil {
		return fmt.Errorf("determine the session type: %w", err)
	}
	if interactive {
		// Someone typed --windows-service in a console. Refusing beats hanging in
		// svc.Run waiting for an SCM that will never call.
		return fmt.Errorf("--windows-service is only valid when started by the Service Control Manager; " +
			"run `trust-proxy serve` without it")
	}
	return svc.Run(serviceName, &gatewayService{run: fn})
}

// serviceName must match what `service install` registered.
const serviceName = "trust-proxy"

type gatewayService struct{ run func() error }

func (g *gatewayService) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	// The gateway's own start is not instant (config parse, box build, and in TUN
	// mode the interface). Report Running as soon as it has not failed outright,
	// and let a failure come back through done — a service that reports Running and
	// then stops is diagnosable; one that never reports anything is not.
	done := make(chan error, 1)
	go func() { done <- g.run() }()
	s <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			// The gateway exited by itself. Exit non-zero so the SCM's
			// restart-on-failure policy applies; zero would read as "stopped on
			// purpose" and it would stay down.
			if err != nil {
				logging.L().Error().Err(err).Msg("gateway exited")
				s <- svc.Status{State: svc.Stopped}
				return false, 1
			}
			s <- svc.Status{State: svc.Stopped}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				requestStop()
				// Wait for the gateway to unwind: in TUN mode it has a network to
				// put back, and being killed halfway is how a machine ends up with
				// no route at all. The SCM's own timeout is the backstop.
				<-done
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				// Unexpected control codes are not worth failing over.
				s <- c.CurrentStatus
			}
		}
	}
}
