// Package logging owns the process-wide logging stack. Nothing here is
// hand-rolled: zerolog encodes, diode decouples, lumberjack rotates.
//
//	our events ──> zerolog ──┐
//	                          ├──> diode ring buffer ──> lumberjack (rotating file)
//	sing-box stdio ──> pipe ─┘        (never blocks)        (size/age/gzip)
//
// Why the middle stage matters for a proxy: sing-box formats and writes one line
// per connection (and per DNS answer) *synchronously, on the connection
// goroutine* (log/observable.go: `l.writer.Write(...)`). With a plain file as the
// sink, every accepted connection pays a disk write — and a rotation (rename +
// gzip) stalls forwarding. diode turns that into a lock-free ring push: writers
// never wait on the disk, and if the sink can't keep up the ring drops lines and
// reports the count instead of applying backpressure to traffic.
//
// Why the pipe: sing-box's own logger writes to stderr and offers no writer
// injection (only an additive PlatformLogWriter hook, which does not stop the
// stderr write). Re-pointing fd 1/2 at a pipe puts one memcpy-to-kernel-buffer
// on the hot path instead of a disk write, and catches everything else that
// writes to stdio too.
package logging

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Ring/rotation defaults. The ring is sized for a burst of log lines, not for
// throughput: at ~200 B/line, 16k slots is a few MB of headroom.
const (
	DefaultMaxSizeMB  = 32
	DefaultMaxBackups = 3
	ringSlots         = 16 << 10
	// 0 => diode uses a waiter instead of a poller: the drain goroutine wakes on
	// the write itself, so lines hit the file immediately and there are no idle
	// timer wakeups.
	ringPoll      = 0
	lineBufferMax = 1 << 20 // a single log line can't exceed this
)

// Options configures Setup.
type Options struct {
	// Path is the rotating log file. Empty => log to stderr, no rotation and no
	// stdio capture (the foreground case: the terminal is the log).
	Path         string
	MaxSizeMB    int  // rotate past this size; 0 => DefaultMaxSizeMB
	MaxBackups   int  // rotated files to keep; 0 => DefaultMaxBackups
	MaxAgeDays   int  // delete rotated files older than this; 0 => by count only
	Compress     bool // gzip rotated files
	CaptureStdio bool // re-point fd 1/2 into the ring (daemon: sing-box logs)
}

var (
	mu     sync.Mutex
	logger = newConsoleLogger(os.Stderr)
	sink   io.Writer // the ring, once Setup installed one
)

// Sink returns the async ring writer, or nil when logging goes to a terminal.
// Handed to sing-box as box.Options.DefaultLogWriter so its per-connection log
// lines become a ring push on the connection goroutine instead of a disk write.
func Sink() io.Writer {
	mu.Lock()
	defer mu.Unlock()
	return sink
}

// L returns the process logger. Safe before Setup (writes to stderr).
func L() *zerolog.Logger {
	mu.Lock()
	defer mu.Unlock()
	l := logger
	return &l
}

// Setup installs the stack and returns a stop func that drains the ring and
// closes the file. Calling it twice replaces the logger; the previous stop func
// must be called by the caller.
func Setup(o Options) (stop func(), err error) {
	if o.Path == "" {
		set(newConsoleLogger(os.Stderr))
		return func() {}, nil
	}
	if o.MaxSizeMB <= 0 {
		o.MaxSizeMB = DefaultMaxSizeMB
	}
	if o.MaxBackups <= 0 {
		o.MaxBackups = DefaultMaxBackups
	}
	rotating := &lumberjack.Logger{
		Filename:   o.Path,
		MaxSize:    o.MaxSizeMB,
		MaxBackups: o.MaxBackups,
		MaxAge:     o.MaxAgeDays,
		Compress:   o.Compress,
	}
	ring := newRing(rotating, nil)

	set(zerolog.New(&ring).With().Timestamp().Logger())
	setSink(&ring)

	stopStdio := func() {}
	if o.CaptureStdio {
		s, err := captureStdio(&ring)
		if err != nil {
			_ = ring.Close()
			_ = rotating.Close()
			return func() {}, err
		}
		stopStdio = s
	}
	return func() {
		stopStdio()
		_ = ring.Close() // drains the ring into lumberjack
		_ = rotating.Close()
		set(newConsoleLogger(os.Stderr))
		setSink(nil)
	}, nil
}

// newRing wraps sink in the lock-free ring that keeps disk I/O off the writers'
// goroutines. When the ring is full the oldest entries are overwritten and the
// loss is reported (into the ring itself — losing the report is better than
// making a proxy wait on its own log). onDrop overrides that for tests.
func newRing(sink io.Writer, onDrop func(missed int)) diode.Writer {
	var ring diode.Writer
	drop := onDrop
	if drop == nil {
		drop = func(missed int) {
			fmt.Fprintf(&ring, `{"level":"warn","dropped":%d,"message":"log ring full, lines dropped"}`+"\n", missed)
		}
	}
	ring = diode.NewWriter(sink, ringSlots, ringPoll, drop)
	return ring
}

func set(l zerolog.Logger) {
	mu.Lock()
	logger = l
	mu.Unlock()
}

func setSink(w io.Writer) {
	mu.Lock()
	sink = w
	mu.Unlock()
}

// newConsoleLogger is the foreground/pre-Setup logger: human-readable, no ring
// (a terminal is not a hot path).
func newConsoleLogger(w io.Writer) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{Out: w, TimeFormat: time.RFC3339}).With().Timestamp().Logger()
}

// captureStdio re-points stdout/stderr at a pipe and forwards it into sink one
// line at a time, so third-party lines (sing-box) stay intact as ring entries.
func captureStdio(sink io.Writer) (stop func(), err error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	if err := redirectStdio(w); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64<<10), lineBufferMax)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			if line == "" {
				continue
			}
			_, _ = io.WriteString(sink, line+"\n")
		}
		_ = r.Close()
	}()
	return func() {
		_ = w.Close()
		// fd 1/2 are dup'd copies of the write end, so the scanner only sees EOF
		// once those go away (at exit). Never block shutdown on it.
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}, nil
}

// Printf adapts the stack to callback APIs that take a printf-shaped logger
// (threatfeed's progress logf). Structured events are preferred everywhere else.
func Printf(format string, args ...any) {
	L().Info().Msgf(format, args...)
}
