package service

import (
	"path/filepath"
	"strings"
	"testing"
)

// The Windows service's arguments cannot be verified on the machine most of this
// is written on, so the parts that are pure string work are tested here — a
// wrong flag list means a service that installs and then refuses to start, with
// the reason only visible in the Windows event log.
func TestServiceArgsCarryTheSCMFlagAndEveryPath(t *testing.T) {
	// Absolute *for the host running the test*: validate() asks filepath.IsAbs,
	// which is per-OS, and a hardcoded C:\… would be "relative" on the machine most
	// of this is written on. What is under test is the flag list, not path syntax.
	base := filepath.Join(string(filepath.Separator), "ProgramData", "trust-proxy")
	c := Config{
		Binary:     filepath.Join(base, "bin", "trust-proxy.exe"),
		ConfigPath: filepath.Join(base, "config.json"),
		DataDir:    base,
		APIAddr:    "127.0.0.1:21585",
		LogPath:    filepath.Join(base, "serve.log"),
	}
	args, err := c.serviceArgs()
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "serve" {
		t.Fatalf("first argument = %q, want serve", args[0])
	}
	// Without this the process runs as a plain foreground gateway, never reports
	// Running, and the SCM kills it when the start timeout expires.
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--windows-service") {
		t.Fatalf("the SCM flag is missing: %v", args)
	}
	for _, want := range []string{c.ConfigPath, c.DataDir, c.APIAddr, c.LogPath} {
		if !strings.Contains(joined, want) {
			t.Fatalf("%q is not in the argument list: %v", want, args)
		}
	}
	// Each path must be its own argument — the SCM passes argv, so a path with a
	// space is safe here as long as it is not glued to its flag.
	for i, a := range args {
		if strings.HasPrefix(a, "--") && strings.Contains(a, "=") {
			t.Fatalf("argument %d (%q) glues a flag to its value", i, a)
		}
	}
	// Installing must never turn capture on by itself.
	if strings.Contains(joined, "--mode") {
		t.Fatalf("no mode was configured, so none must be pinned: %v", args)
	}
}

func TestServiceArgsRefuseAnIncompleteConfig(t *testing.T) {
	// The same validation as the plist and the unit: a relative path has nothing
	// to resolve against when the SCM starts the process at boot.
	abs := filepath.Join(string(filepath.Separator), "d")
	c := Config{
		Binary: filepath.Join(abs, "tp.exe"), ConfigPath: "config.json",
		DataDir: abs, APIAddr: "127.0.0.1:1", LogPath: filepath.Join(abs, "l.log"),
	}
	if _, err := c.serviceArgs(); err == nil {
		t.Fatal("a relative config path must be refused")
	}
}

// firstArg reads back what the SCM stores as one command-line string, which is
// how `service status` notices a stale binary path.
func TestFirstArg(t *testing.T) {
	cases := map[string]string{
		`"C:\Program Files\trust-proxy\trust-proxy.exe" serve --data "C:\d"`: `C:\Program Files\trust-proxy\trust-proxy.exe`,
		`C:\tp\trust-proxy.exe serve`:                                        `C:\tp\trust-proxy.exe`,
		`C:\tp\trust-proxy.exe`:                                              `C:\tp\trust-proxy.exe`,
		``:                                                                   ``,
	}
	for in, want := range cases {
		if got := firstArg(in); got != want {
			t.Fatalf("firstArg(%q) = %q, want %q", in, got, want)
		}
	}
}
