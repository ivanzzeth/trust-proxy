package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/credentials"
	"github.com/ivanzzeth/trust-proxy/internal/paths"
	"github.com/ivanzzeth/trust-proxy/internal/service"
)

// `env` is the single source of truth about this machine, for anything that is
// not the Go binary itself.
//
// It exists because the desktop shell used to work all of this out again in
// Rust: its own copy of where the data directory is, its own guess at where the
// gateway binary lives, its own hand-rolled probe for whether the console is
// there. Three mirrors of rules that live in Go, drifting independently — and
// the shell is the one place where drift is invisible, because it shows a splash
// screen instead of an error. Now the shell asks, and there is one answer.
//
// Deliberately answerable without root and without a running gateway: "nothing
// is installed and I am not privileged" is a state this has to describe, not
// fail on.

type envServiceInfo struct {
	Supported      bool   `json:"supported"`
	Installed      bool   `json:"installed"`
	Running        bool   `json:"running"`
	Detail         string `json:"detail,omitempty"`
	File           string `json:"file,omitempty"`
	Program        string `json:"program,omitempty"`
	ProgramMissing bool   `json:"program_missing"`
	// DefinitionUnreadable separates "we cannot read the definition" from "there
	// is no program": both leave Program empty, but only the first means the
	// staleness checks that key off it are silently switched off.
	DefinitionUnreadable bool `json:"definition_unreadable,omitempty"`
}

type envGatewayInfo struct {
	Healthy bool `json:"healthy"`
	// Console reports that the gateway answering on this address actually has a
	// console in it. A gateway installed from a binary built without the UI is
	// healthy, serves the API, and fills every page with "dashboard not built" —
	// worth naming as its own state rather than letting a window show it.
	Console bool `json:"console"`
	// Version is the build actually answering, which is not necessarily this one.
	Version string `json:"version,omitempty"`
	// Managed reports that the gateway answering is the copy the service manager
	// owns, rather than a `serve` somebody started by hand.
	Managed bool `json:"managed"`
	// Stale reports that the gateway answering is a different build from this
	// binary — on a desktop that means the app was upgraded and the daemon was
	// not. Without it an upgrade is a silent no-op: the new app attaches to the
	// old daemon and every page looks exactly right.
	Stale bool `json:"stale"`
}

// Action is what should happen next on this machine, decided here rather than in
// whatever is asking.
//
// The desktop shell used to decide with one question — "does anything answer?" —
// and attach whenever the answer was yes. That is right in exactly one of the
// four cases and silently wrong in two of them: it shows a stale daemon's console
// after an upgrade, and it never offers to take over a gateway somebody left
// running by hand. Naming the four states in one place is what stops the window
// and the CLI from disagreeing about them.
const (
	ActionAttach      = "attach"   // the system gateway is running and current
	ActionUpdate      = "update"   // it is running but older than this build
	ActionTakeover    = "takeover" // something else holds the port; it is not the service
	ActionInstall     = "install"  // nothing here yet
	ActionRepair      = "repair"   // installed but not running
	ActionUnsupported = "unsupported"
)

type envInfo struct {
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
	Version     string `json:"version"`
	Privileged  bool   `json:"privileged"`
	CanTUN      bool   `json:"can_tun"`
	DataDir     string `json:"data_dir"`
	ManagedBin  string `json:"managed_binary"`
	Credentials string `json:"credentials_path,omitempty"`
	APIAddr     string `json:"api_addr"`
	ConsoleURL  string `json:"console_url"`
	// Elevation names how this platform asks for administrator rights, so a UI can
	// say which prompt is about to appear instead of "authorize this".
	Elevation string `json:"elevation"`
	// InstallCommand is the exact thing to run with those rights. The shell runs
	// this rather than assembling its own argument list — an earlier version built
	// its own and quietly passed a --data that undid the machine-wide rule.
	InstallCommand string         `json:"install_command"`
	Service        envServiceInfo `json:"service"`
	Gateway        envGatewayInfo `json:"gateway"`
	// Action is what should happen next: attach | update | takeover | install |
	// repair | unsupported. See the constants above.
	Action string `json:"action"`
}

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Where everything is on this machine, and what state it is in",
	Long: "One answer, for people and for the desktop app: which directories are in use,\n" +
		"whether the service is installed and running, whether the gateway answers, and\n" +
		"how this platform asks for administrator rights.",
	RunE: func(cmd *cobra.Command, args []string) error {
		e := collectEnv()
		return out(e, func() {
			fmt.Printf("%-16s %s/%s\n", "platform:", e.Platform, e.Arch)
			fmt.Printf("%-16s %s\n", "version:", e.Version)
			fmt.Printf("%-16s %v (can tun: %v)\n", "privileged:", e.Privileged, e.CanTUN)
			fmt.Printf("%-16s %s\n", "data:", e.DataDir)
			fmt.Printf("%-16s %s\n", "managed binary:", e.ManagedBin)
			if e.Credentials != "" {
				fmt.Printf("%-16s %s\n", "credentials:", e.Credentials)
			}
			fmt.Printf("%-16s %s\n", "api:", e.APIAddr)
			if !e.Service.Supported {
				fmt.Printf("%-16s not implemented on %s\n", "service:", e.Platform)
			} else {
				fmt.Printf("%-16s installed=%v running=%v %s\n", "service:",
					e.Service.Installed, e.Service.Running, e.Service.Detail)
				if e.Service.Program != "" {
					fmt.Printf("%-16s %s\n", "  program:", e.Service.Program)
				}
				if e.Service.ProgramMissing {
					fmt.Printf("%-16s ⚠ the program is gone; the service manager retries it at every boot\n", "")
				}
				if e.Service.DefinitionUnreadable {
					fmt.Printf("%-16s ⚠ %s is not readable; which binary it runs cannot be checked\n", "", e.Service.File)
				}
			}
			fmt.Printf("%-16s healthy=%v console=%v managed=%v version=%s\n", "gateway:",
				e.Gateway.Healthy, e.Gateway.Console, e.Gateway.Managed, dash(e.Gateway.Version))
			fmt.Printf("%-16s %s\n", "next:", e.Action)
			switch e.Action {
			case ActionInstall:
				fmt.Printf("\nnothing is installed yet. Set it up with:\n    sudo %s\n", e.InstallCommand)
			case ActionUpdate:
				fmt.Printf("\nthe running gateway is %s but this build is %s — the daemon was not\n"+
					"updated. Replace it with:\n    sudo %s\n", e.Gateway.Version, e.Version, e.InstallCommand)
			case ActionTakeover:
				fmt.Printf("\nsomething is on %s that is not the system service (a `serve` started by\n"+
					"hand, or one left over from an older install). Take it over with:\n    sudo %s --takeover\n",
					e.APIAddr, e.InstallCommand)
			case ActionRepair:
				fmt.Printf("\nthe service is installed but not running. Reinstalling is the repair:\n    sudo %s\n",
					e.InstallCommand)
			}
		})
	},
}

func collectEnv() envInfo {
	e := envInfo{
		Platform:   runtime.GOOS,
		Arch:       runtime.GOARCH,
		Version:    version,
		Privileged: paths.Privileged(),
		CanTUN:     paths.CanTUN(),
		DataDir:    paths.Data(),
		ManagedBin: paths.ManagedBinary(),
		APIAddr:    apiAddr,
		ConsoleURL: "http://" + apiAddr + "/",
		Elevation:  elevationMechanism(),
	}
	if p, err := credentials.Path(); err == nil {
		e.Credentials = p
	}
	self, err := os.Executable()
	if err != nil {
		self = "trust-proxy"
	}
	e.InstallCommand = fmt.Sprintf("%s install --api-addr %s", self, apiAddr)

	installed, running, detail := service.Status()
	program := service.Program()
	e.Service = envServiceInfo{
		Supported: service.File() != "" || runtime.GOOS == "windows",
		Installed: installed, Running: running, Detail: detail,
		File: service.File(), Program: program,
		ProgramMissing:       service.BinaryMissing(program),
		DefinitionUnreadable: service.DefinitionUnreadable(),
	}
	e.Gateway = probeGateway(apiAddr)
	// Stale is decided here, against *this* binary: on a desktop, "this binary" is
	// the sidecar inside the app that was just opened, so a mismatch is exactly
	// "you upgraded the app and the daemon is still the old one".
	e.Gateway.Stale = e.Gateway.Healthy && e.Gateway.Version != "" && e.Gateway.Version != version
	e.Action = decideAction(e)
	return e
}

// decideAction picks the one thing that should happen next.
func decideAction(e envInfo) string {
	switch {
	case e.Gateway.Healthy && e.Gateway.Managed && !e.Gateway.Stale:
		return ActionAttach
	case e.Gateway.Healthy && e.Gateway.Managed:
		return ActionUpdate
	case e.Gateway.Healthy:
		// Something holds the port and it is not the managed copy: a `serve` in a
		// terminal, or a gateway left over from before this machine had a service.
		// Attaching to it is what made an upgrade look like nothing happened.
		if !e.Service.Supported {
			return ActionUnsupported
		}
		return ActionTakeover
	case !e.Service.Supported:
		return ActionUnsupported
	case e.Service.Installed:
		return ActionRepair
	default:
		return ActionInstall
	}
}

// probeGateway asks what is actually on the port: whether anything answers,
// which build it is, whether it is the copy the service manager owns, and
// whether it can show a console.
//
// /api/health carries the build and the managed flag, and only to loopback —
// see the handler for why. An older gateway omits them, which reads as "unknown
// build, not managed" and lands on the takeover offer rather than a silent
// attach. That is the right way to be wrong here.
func probeGateway(addr string) envGatewayInfo {
	var g envGatewayInfo
	c := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := c.Get("http://" + addr + "/api/health")
	if err != nil {
		return g
	}
	health, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return g
	}
	g.Healthy = true
	var reported struct {
		Version string `json:"version"`
		Managed bool   `json:"managed"`
	}
	if json.Unmarshal(health, &reported) == nil {
		g.Version, g.Managed = reported.Version, reported.Managed
	}
	root, err := c.Get("http://" + addr + "/")
	if err != nil {
		return g
	}
	defer root.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(root.Body, 2<<10))
	// The one marker the console-less build serves. Matching a string is crude,
	// but it is matched in exactly one place now instead of once per language.
	g.Console = root.StatusCode == http.StatusOK && !bytes.Contains(body, []byte("dashboard not built"))
	return g
}

// elevationMechanism names how this platform asks for administrator rights.
//
// Linux deliberately has no sudo fallback: from a GUI there is no terminal to
// ask on, so it would either fail silently or — on a passwordless-sudo box —
// elevate with no prompt at all.
func elevationMechanism() string {
	switch runtime.GOOS {
	case "darwin":
		return "osascript"
	case "windows":
		return "uac"
	case "linux":
		if _, err := exec.LookPath("pkexec"); err == nil {
			return "pkexec"
		}
		return "" // no graphical elevation here; a terminal is the only way
	default:
		return ""
	}
}
