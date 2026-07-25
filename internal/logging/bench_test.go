package logging

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The comparison that matters for a proxy: sing-box writes one line per
// connection from the connection goroutine. BenchmarkFileWrite is today's cost
// (syscall to the log file on the hot path); BenchmarkRingWrite is what the ring
// turns it into.
func BenchmarkFileWrite(b *testing.B) {
	f, err := os.CreateTemp(b.TempDir(), "direct-*.log")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	benchWrite(b, f)
}

func BenchmarkRingWrite(b *testing.B) {
	f, err := os.CreateTemp(b.TempDir(), "ring-*.log")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	ring := newRing(f, func(int) {})
	defer ring.Close()
	benchWrite(b, &ring)
}

func benchWrite(b *testing.B, w io.Writer) {
	line := []byte("+0800 2026-07-26 01:02:03 INFO [1234567890 0ms] inbound/tun[tun-in]: inbound connection to 93.184.216.34:443\n")
	b.SetBytes(int64(len(line)))
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			_, _ = w.Write(line)
		}
	})
}

var _ = filepath.Join
