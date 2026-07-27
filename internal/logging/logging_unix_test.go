//go:build !windows

package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// withRealStdio saves and restores fd 1/2 around fn, so a test can exercise the
// real dup2 capture path without losing the test binary's own output. Restoring
// also drops the last references to the pipe write end, which is what lets the
// scanner see EOF.
func withRealStdio(t *testing.T, fn func()) {
	t.Helper()
	saveOut, err := unix.Dup(int(os.Stdout.Fd()))
	if err != nil {
		t.Fatalf("dup stdout: %v", err)
	}
	saveErr, err := unix.Dup(int(os.Stderr.Fd()))
	if err != nil {
		t.Fatalf("dup stderr: %v", err)
	}
	defer func() {
		_ = unix.Dup2(saveOut, int(os.Stdout.Fd()))
		_ = unix.Dup2(saveErr, int(os.Stderr.Fd()))
		_ = unix.Close(saveOut)
		_ = unix.Close(saveErr)
	}()
	fn()
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// Our structured events and sing-box's stdio must both reach the file: sing-box
// logs via stderr, so capturing only stdout would silently drop the bulk of it.
func TestSetupCapturesOwnEventsAndStdio(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve.log")
	var stop func()
	withRealStdio(t, func() {
		s, err := Setup(Options{Path: path, MaxSizeMB: 8, MaxBackups: 2, CaptureStdio: true})
		if err != nil {
			t.Fatalf("Setup: %v", err)
		}
		stop = s
		L().Info().Str("who", "trust-proxy").Msg("own-event")
		fmt.Fprintln(os.Stdout, "line-from-stdout")
		fmt.Fprintln(os.Stderr, "line-from-stderr")
		time.Sleep(100 * time.Millisecond) // let the scanner drain the pipe
	})
	stop()

	body := readFile(t, path)
	for _, want := range []string{`"own-event"`, `"who":"trust-proxy"`, "line-from-stdout", "line-from-stderr"} {
		if !strings.Contains(body, want) {
			t.Fatalf("log missing %q, got:\n%s", want, body)
		}
	}
}

// The whole point: an unattended gateway can no longer grow a 91 MB log. The
// live file stays near the cap and old generations are bounded by MaxBackups.
func TestSetupRotatesAndCapsBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serve.log")
	stop, err := Setup(Options{Path: path, MaxSizeMB: 1, MaxBackups: 2})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	pad := strings.Repeat("x", 1024)
	for i := 0; i < 4096; i++ { // ~4 MB => several rotations
		L().Info().Int("i", i).Str("pad", pad).Msg("filler")
	}
	stop() // drains the ring

	// lumberjack prunes old generations on a background goroutine, so the count
	// is bounded *eventually*, not at the instant the last write returns. Reading
	// the directory once passed on the machine this was written on and failed the
	// first time CI ran it on Linux, with three backups where two were expected —
	// a scheduling difference, not a leak. Poll for the bound instead of racing it.
	backups := func() []string {
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
	var last []string
	deadline := time.Now().Add(10 * time.Second)
	for {
		last = backups()
		if len(last) > 0 && len(last) <= 2 {
			break
		}
		if time.Now().After(deadline) {
			if len(last) == 0 {
				t.Fatal("never rotated")
			}
			t.Fatalf("MaxBackups=2 still exceeded after 10s: %v", last)
		}
		time.Sleep(50 * time.Millisecond)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 2<<20 {
		t.Fatalf("live log is %d bytes, want bounded near the 1 MB cap", fi.Size())
	}
}

// blockingSink stands in for a stalled disk: it never returns until released.
type blockingSink struct{ release chan struct{} }

func (b *blockingSink) Write(p []byte) (int, error) {
	<-b.release
	return len(p), nil
}

// A wedged sink must not stall the writers — that is the reason the ring is
// there. If diode ever applied backpressure, every accepted connection would
// wait on the log.
func TestRingNeverBlocksWriters(t *testing.T) {
	sink := &blockingSink{release: make(chan struct{})}
	ring := newRing(sink, func(int) {})
	defer func() {
		close(sink.release)
		_ = ring.Close()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < ringSlots*2; i++ { // more than the ring holds
			_, _ = ring.Write([]byte("blocked-sink line\n"))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("writes blocked on a stalled sink — the ring must drop, not wait")
	}
}
