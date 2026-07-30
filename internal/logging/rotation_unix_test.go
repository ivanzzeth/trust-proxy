//go:build !windows

package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Changing retention at runtime must not cost us the two things Setup wired up:
// the ring (writers never wait on the disk) and the fd 1/2 capture (sing-box
// logs to stderr and offers no writer injection).
//
// The tempting implementation — re-run Setup with the new numbers — passes a
// test that only checks the new policy took effect, while silently tearing down
// and rebuilding the stdio pipe. This asserts on stdio *after* the swap, so
// that implementation fails here.
func TestSetRotationKeepsRingAndStdioCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.log")
	var stop func()
	withRealStdio(t, func() {
		s, err := Setup(Options{Path: path, MaxSizeMB: 8, MaxBackups: 2, CaptureStdio: true})
		if err != nil {
			t.Fatalf("Setup: %v", err)
		}
		stop = s
		L().Info().Msg("before-swap")
		fmt.Fprintln(os.Stderr, "stderr-before-swap")

		if err := SetRotation(Options{MaxSizeMB: 4, MaxBackups: 7, MaxAgeDays: 3, Compress: true}); err != nil {
			t.Fatalf("SetRotation: %v", err)
		}

		L().Info().Msg("after-swap")
		fmt.Fprintln(os.Stderr, "stderr-after-swap")
		fmt.Fprintln(os.Stdout, "stdout-after-swap")
		time.Sleep(150 * time.Millisecond) // let the scanner drain the pipe
	})
	// Read the policy while the stack is still installed: stop() uninstalls it.
	got, ok := Rotation()
	stop()

	body := readFile(t, path)
	for _, want := range []string{"before-swap", "stderr-before-swap", "after-swap", "stderr-after-swap", "stdout-after-swap"} {
		if !strings.Contains(body, want) {
			t.Fatalf("log missing %q after SetRotation — the swap disturbed the stack. Got:\n%s", want, body)
		}
	}
	if !ok {
		t.Fatal("Rotation() reports no file logger after SetRotation")
	}
	if got.MaxSizeMB != 4 || got.MaxBackups != 7 || got.MaxAgeDays != 3 || !got.Compress {
		t.Fatalf("Rotation() = %+v, want the values just set", got)
	}
	// Path is a property of the installed stack, not of the policy: a caller
	// that leaves it blank must not silently move the log file.
	if got.Path != path {
		t.Fatalf("SetRotation moved the log file to %q", got.Path)
	}
}

// The new size cap has to actually reach lumberjack. Setting it smaller and
// writing past it must rotate; an implementation that stores the number without
// rebuilding the logger keeps rotating at the old cap.
func TestSetRotationAppliesTheNewSizeCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serve.log")
	stop, err := Setup(Options{Path: path, MaxSizeMB: 500, MaxBackups: 4})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	defer stop()

	pad := strings.Repeat("x", 1024)
	for i := 0; i < 512; i++ { // ~0.5 MB: nowhere near the 500 MB cap
		L().Info().Int("i", i).Str("pad", pad).Msg("filler")
	}
	if n := len(backupsIn(t, dir)); n != 0 {
		t.Fatalf("rotated %d times under a 500 MB cap", n)
	}

	if err := SetRotation(Options{MaxSizeMB: 1, MaxBackups: 4}); err != nil {
		t.Fatalf("SetRotation: %v", err)
	}
	for i := 0; i < 3072; i++ { // ~3 MB against the new 1 MB cap
		L().Info().Int("i", i).Str("pad", pad).Msg("filler")
	}

	deadline := time.Now().Add(10 * time.Second)
	for len(backupsIn(t, dir)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("never rotated after lowering the cap to 1 MB — the new policy did not reach lumberjack")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A foreground run logs to the terminal, which does not rotate. Saying so
// beats pretending the change was applied.
func TestSetRotationWithoutAFileLoggerReportsIt(t *testing.T) {
	stop, err := Setup(Options{}) // no Path => console
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := SetRotation(Options{MaxSizeMB: 4}); err == nil {
		t.Fatal("SetRotation claimed success with no rotating file installed")
	}
	if _, ok := Rotation(); ok {
		t.Fatal("Rotation() reports a policy for a console logger")
	}
}

// -1 is how the CLI has always spelled "don't rotate" (--log-max-size 0 in the
// flag world, where 0 could still mean unset). lumberjack has no off switch, so
// this must become a ceiling that is never reached rather than a 0 that
// lumberjack silently reads as "use my default 100 MB".
func TestNoRotationIsNotSilentlyTheDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serve.log")
	stop, err := Setup(Options{Path: path, MaxSizeMB: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	got, ok := Rotation()
	if !ok {
		t.Fatal("no rotation policy installed")
	}
	if got.MaxSizeMB != noRotationMB {
		t.Fatalf("MaxSizeMB = %d, want the never-reached ceiling %d", got.MaxSizeMB, noRotationMB)
	}
}

func backupsIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.Name() != "serve.log" {
			out = append(out, e.Name())
		}
	}
	return out
}
