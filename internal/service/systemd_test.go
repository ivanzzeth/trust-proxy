package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func linuxConfig() Config {
	return Config{
		Binary:     "/usr/local/libexec/trust-proxy",
		ConfigPath: "/var/lib/trust-proxy/config.json",
		DataDir:    "/var/lib/trust-proxy",
		APIAddr:    "127.0.0.1:21585",
		LogPath:    "/var/lib/trust-proxy/serve.log",
	}
}

func TestUnitRunsTheGatewayWithTheGivenPaths(t *testing.T) {
	u, err := linuxConfig().Unit()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/usr/local/libexec/trust-proxy serve -c /var/lib/trust-proxy/config.json --data /var/lib/trust-proxy --api-addr 127.0.0.1:21585",
		"Restart=always",
		"WantedBy=multi-user.target",
		"CAP_NET_ADMIN", // TUN would not work without it
	} {
		if !strings.Contains(u, want) {
			t.Fatalf("unit is missing %q:\n%s", want, u)
		}
	}
	// Installing must never turn capture on by itself.
	if strings.Contains(u, "--mode") {
		t.Fatalf("a config with no mode must not pin one:\n%s", u)
	}
	// network-online.target may never be reached on a machine where we *are* the
	// network path, and a gateway that waits for it never starts.
	if strings.Contains(u, "network-online.target") {
		t.Fatalf("unit must not wait for network-online.target:\n%s", u)
	}
}

func TestUnitCarriesAnExplicitMode(t *testing.T) {
	c := linuxConfig()
	c.Mode = "tun"
	u, err := c.Unit()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "--mode tun") {
		t.Fatalf("mode not in ExecStart:\n%s", u)
	}
}

// systemd splits ExecStart on whitespace, so an unquoted path with a space in it
// silently becomes two arguments and the daemon comes up with the wrong data dir.
func TestUnitQuotesPathsWithSpaces(t *testing.T) {
	c := linuxConfig()
	c.DataDir = "/home/ivan/My Gateway/data"
	c.ConfigPath = "/home/ivan/My Gateway/data/config.json"
	c.LogPath = "/home/ivan/My Gateway/data/serve.log"
	u, err := c.Unit()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, `--data "/home/ivan/My Gateway/data"`) {
		t.Fatalf("data dir with a space is not quoted:\n%s", u)
	}
	if !strings.Contains(u, `StandardOutput=append:"/home/ivan/My Gateway/data/serve.log"`) {
		t.Fatalf("log path with a space is not quoted:\n%s", u)
	}
}

// A % in a path is a systemd specifier; unescaped, %h would expand to the home
// directory and the daemon would write somewhere else entirely.
func TestUnitEscapesSpecifiers(t *testing.T) {
	c := linuxConfig()
	c.DataDir = "/srv/100%hot/data"
	u, err := c.Unit()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, `100%%hot`) {
		t.Fatalf("%% not escaped:\n%s", u)
	}
}

func TestUnitRefusesRelativePaths(t *testing.T) {
	c := linuxConfig()
	c.DataDir = "data"
	if _, err := c.Unit(); err == nil {
		t.Fatal("a relative data dir must be refused: systemd has nothing to resolve it against")
	}
}

func TestProgramFromUnitReadsExecStartBack(t *testing.T) {
	dir := t.TempDir()
	old := UnitPath
	UnitPath = filepath.Join(dir, "trust-proxy.service")
	defer func() { UnitPath = old }()

	c := linuxConfig()
	c.Binary = "/opt/My Apps/trust-proxy" // the quoted case, which is the hard one
	c.ConfigPath, c.DataDir, c.LogPath = "/var/lib/tp/config.json", "/var/lib/tp", "/var/lib/tp/serve.log"
	u, err := c.Unit()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(UnitPath, []byte(u), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ProgramFromUnit(); got != c.Binary {
		t.Fatalf("ProgramFromUnit() = %q, want %q", got, c.Binary)
	}
}
