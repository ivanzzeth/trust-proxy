package service

import (
	"os"
	"path/filepath"
	"strings"
)

// systemd is the Linux equivalent of the launchd path in this package: same
// Config, same anti-brick rules (one command removes it, installing never turns
// TUN on by itself, the unit name is ours alone), different init system.
//
// Rendered here rather than in install_linux.go so the unit can be tested on any
// OS — a broken unit file is a machine that does not come back after a reboot,
// which is not something to find out on the machine.

// UnitName is the systemd unit. UnitPath is where a system unit lives.
const UnitName = "trust-proxy.service"

// A var, not a const, only so tests can redirect it away from a root-owned path.
var UnitPath = "/etc/systemd/system/" + UnitName

// Unit renders the systemd service file.
func (c Config) Unit() (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	// serveFlags, not a second hand-written list. This used to build its own, and
	// the two had already drifted: systemd never passed --console, whose default is
	// a relative path a daemon cannot resolve, so a Linux install without an
	// embedded UI came up answering "dashboard not built" — the exact failure
	// serveFlags' comment warns about, in the one place that wasn't using it.
	args := append([]string{c.Binary}, c.serveFlags()...)
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = systemdQuote(a)
	}

	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=trust-proxy egress gateway\n")
	b.WriteString("Documentation=https://github.com/ivanzzeth/trust-proxy\n")
	// The gateway wants the network stack up, but must not wait for
	// network-online.target: on a machine where *we* are the network path, that
	// target may never be reached, and the gateway would never start.
	b.WriteString("After=network.target\n")
	b.WriteString("Wants=network.target\n\n")

	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	// systemd owns the process lifecycle, so serve runs in the foreground. Mark
	// it as the service child to install the in-process diode+lumberjack stack;
	// otherwise retention.json never governs serve.log.
	b.WriteString("Environment=TP_DAEMON=1\n")
	b.WriteString("ExecStart=" + strings.Join(quoted, " ") + "\n")
	// Same reasoning as launchd's KeepAlive: a gateway that stays down stops
	// enforcing policy. RestartSec keeps a config error from becoming a spin.
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=3\n")
	// TUN needs these; the rest of the capabilities are dropped. Running as root
	// with everything is what a gateway usually does — this is strictly less.
	b.WriteString("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n")
	b.WriteString("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER\n")
	// /dev/net/tun has to stay reachable, so DevicePolicy is left alone.
	b.WriteString("StateDirectory=trust-proxy\n")
	b.WriteString("WorkingDirectory=" + systemdQuote(filepath.Dir(c.Binary)) + "\n")
	// serve owns serve.log through lumberjack. A second systemd append fd would
	// bypass rotation and can keep writing into a renamed generation. Journal is
	// a bounded fallback for failures before logging.Setup is installed.
	b.WriteString("StandardOutput=journal\n")
	b.WriteString("StandardError=journal\n")
	// A gateway that is killed mid-reconfiguration can leave a machine without a
	// route, so it gets time to put things back (mode revert, tun teardown).
	b.WriteString("TimeoutStopSec=20\n")
	b.WriteString("KillMode=mixed\n\n")

	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String(), nil
}

// systemdQuote quotes a path for a unit's ExecStart.
//
// systemd splits ExecStart on whitespace and does its own unescaping, so a data
// directory with a space in it (a real thing on a desktop) silently becomes two
// arguments — and the daemon comes up with the wrong data dir rather than failing
// loudly.
func systemdQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$%") {
		return s
	}
	// %% escapes a literal % (systemd specifier expansion runs before quoting).
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`)
	return `"` + r.Replace(s) + `"`
}

// ProgramFromUnit reads ExecStart's first word back, so status can show what
// systemd will actually exec and notice a stale path.
func ProgramFromUnit() string {
	data, err := os.ReadFile(UnitPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		v := strings.TrimPrefix(line, "ExecStart=")
		if strings.HasPrefix(v, `"`) {
			if end := strings.Index(v[1:], `"`); end >= 0 {
				return strings.NewReplacer(`\\`, `\`, `\"`, `"`, `%%`, `%`).Replace(v[1 : 1+end])
			}
		}
		return strings.Fields(v)[0]
	}
	return ""
}
