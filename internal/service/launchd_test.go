package service

import (
	"os/exec"
	"strings"
	"testing"
)

func base() Config {
	return Config{
		Binary:     "/usr/local/bin/trust-proxy",
		ConfigPath: "/etc/trust-proxy/config.json",
		DataDir:    "/var/lib/trust-proxy",
		APIAddr:    "127.0.0.1:9096",
		LogPath:    "/var/log/trust-proxy.log",
	}
}

// The plist is the only state an uninstall has to find, and launchd parses it
// with no error reporting a user will ever see — so assert it is well-formed XML
// (via plutil, which is what launchd itself uses) and that it carries the args.
func TestPlistIsValidAndCarriesTheServeArguments(t *testing.T) {
	c := base()
	c.Mode = "tun"
	got, err := c.Plist()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<string>" + Label + "</string>",
		"<string>/usr/local/bin/trust-proxy</string>",
		"<string>serve</string>", "<string>-c</string>", "<string>/etc/trust-proxy/config.json</string>",
		"<string>--data</string>", "<string>/var/lib/trust-proxy</string>",
		"<string>--api-addr</string>", "<string>127.0.0.1:9096</string>",
		"<string>--mode</string>", "<string>tun</string>",
		"<key>RunAtLoad</key>", "<key>KeepAlive</key>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("plist missing %s", want)
		}
	}

	if _, err := exec.LookPath("plutil"); err != nil {
		t.Skip("plutil not available")
	}
	cmd := exec.Command("plutil", "-lint", "-")
	cmd.Stdin = strings.NewReader(got)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("plutil rejected the plist: %v\n%s\n%s", err, out, got)
	}
}

// Mode is opt-in: installing the service must not silently start capturing all
// traffic on a machine where the user never asked for TUN.
func TestPlistOmitsModeWhenNotAsked(t *testing.T) {
	got, err := base().Plist()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "--mode") {
		t.Fatalf("mode must not be forced when unset:\n%s", got)
	}
}

// launchd resolves nothing: a relative path here becomes a daemon that fails at
// every boot, with the failure only visible in a log nobody opens.
func TestRelativePathsAndBadModeAreRefused(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"relative binary": func(c *Config) { c.Binary = "./trust-proxy" },
		"relative config": func(c *Config) { c.ConfigPath = "configs/config.json" },
		"relative data":   func(c *Config) { c.DataDir = "data" },
		"relative log":    func(c *Config) { c.LogPath = "serve.log" },
		"empty binary":    func(c *Config) { c.Binary = "" },
		"empty api addr":  func(c *Config) { c.APIAddr = "" },
		"bogus mode":      func(c *Config) { c.Mode = "wide-open" },
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(&c)
			if _, err := c.Plist(); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

// A data dir or node name with an ampersand would otherwise produce a plist
// launchd cannot parse — and the daemon would just never start.
func TestPlistEscapesXML(t *testing.T) {
	c := base()
	c.DataDir = "/Users/a & b/.trust-proxy"
	got, err := c.Plist()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "/Users/a &amp; b/.trust-proxy") {
		t.Fatalf("XML not escaped:\n%s", got)
	}
	if _, err := exec.LookPath("plutil"); err != nil {
		return
	}
	cmd := exec.Command("plutil", "-lint", "-")
	cmd.Stdin = strings.NewReader(got)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("plutil rejected the escaped plist: %v\n%s", err, out)
	}
}
