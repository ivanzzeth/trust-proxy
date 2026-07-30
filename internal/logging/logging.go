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
	"errors"
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
	// noRotationMB is how "don't rotate" is spelled to lumberjack, which has no
	// off switch: a size ceiling in petabytes is never reached.
	noRotationMB = 1 << 30
	ringSlots    = 16 << 10
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
	rot    *rotator  // the swappable lumberjack behind the ring, once Setup installed one
)

// rotator is the indirection that makes rotation settings changeable at
// runtime. lumberjack exposes no setters and takes its own lock inside Write,
// so the only safe way to change MaxSize/MaxBackups/MaxAge/Compress is to build
// a new *lumberjack.Logger and swap the pointer.
//
// The swap has to happen HERE rather than by re-running Setup, because Setup
// also builds the diode ring and re-points fd 1/2 into it. Tearing that down to
// change a retention number would drop sing-box's own log lines for as long as
// the stdio pipe was being rebuilt (and captureStdio's stop can block for two
// seconds), all to change how many old files are kept.
type rotator struct {
	mu   sync.RWMutex
	lj   *lumberjack.Logger
	opts Options
}

func (r *rotator) Write(p []byte) (int, error) {
	r.mu.RLock()
	lj := r.lj
	r.mu.RUnlock()
	return lj.Write(p)
}

func (r *rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lj.Close()
}

// swap installs a logger built from o, keeping the same file, and closes the
// old one. Only the ring's drain goroutine calls Write, and it does so under
// RLock, so no writer can be inside the old logger when it is closed.
func (r *rotator) swap(o Options) error {
	next := newLumberjack(o)
	r.mu.Lock()
	prev := r.lj
	r.lj = next
	r.opts = o
	r.mu.Unlock()
	if prev != nil {
		return prev.Close()
	}
	return nil
}

func newLumberjack(o Options) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   o.Path,
		MaxSize:    o.MaxSizeMB,
		MaxBackups: o.MaxBackups,
		MaxAge:     o.MaxAgeDays,
		Compress:   o.Compress,
	}
}

// ErrNoRotatingLog is returned by SetRotation when the process logs to a
// terminal, which has no rotation to configure. A sentinel because it is the
// normal state of a foreground run: callers applying a stored policy need to
// distinguish "nothing to do here" from "the policy did not take".
var ErrNoRotatingLog = errors.New("logging: no rotating log file installed (running in the foreground?)")

// SetRotation changes the rotation policy of the running log file without
// disturbing the ring or the stdio capture. Path and CaptureStdio are ignored:
// they are properties of the installed stack, not of the policy.
//
// Returns ErrNoRotatingLog when Setup never installed a file logger.
func SetRotation(o Options) error {
	mu.Lock()
	r := rot
	mu.Unlock()
	if r == nil {
		return ErrNoRotatingLog
	}
	r.mu.RLock()
	cur := r.opts
	r.mu.RUnlock()
	// Path is fixed by Setup; only the policy fields move.
	o.Path = cur.Path
	o.CaptureStdio = cur.CaptureStdio
	normalizeRotation(&o)
	return r.swap(o)
}

// Rotation reports the policy currently in force, or false when logging to a
// terminal.
func Rotation() (Options, bool) {
	mu.Lock()
	r := rot
	mu.Unlock()
	if r == nil {
		return Options{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.opts, true
}

// DefaultOptions is the rotation policy in force when nothing has been
// configured. Exported so /api/defaults can report it rather than have a client
// restate these numbers — a second copy does not fail loudly when this one
// changes, it just starts describing a gateway that no longer exists.
func DefaultOptions() Options {
	return Options{MaxSizeMB: DefaultMaxSizeMB, MaxBackups: DefaultMaxBackups, Compress: true}
}

// normalizeRotation resolves the "unset" spellings. MaxSizeMB < 0 means the
// operator asked for no rotation at all, which lumberjack spells as a size
// ceiling so high it is never reached (it has no explicit off switch).
func normalizeRotation(o *Options) {
	if o.MaxSizeMB < 0 {
		o.MaxSizeMB = noRotationMB
		return
	}
	if o.MaxSizeMB == 0 {
		o.MaxSizeMB = DefaultMaxSizeMB
	}
	if o.MaxBackups <= 0 {
		o.MaxBackups = DefaultMaxBackups
	}
}

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
	normalizeRotation(&o)
	// The ring writes through the rotator, not straight to lumberjack, so the
	// retention policy can be swapped later without rebuilding the ring or the
	// stdio pipe. See rotator's comment.
	rotating := &rotator{lj: newLumberjack(o), opts: o}
	ring := newRing(rotating, nil)

	set(zerolog.New(&ring).With().Timestamp().Logger())
	setSink(&ring)
	setRotator(rotating)

	stopStdio := func() {}
	if o.CaptureStdio {
		s, err := captureStdio(&ring)
		if err != nil {
			_ = ring.Close()
			_ = rotating.Close()
			setRotator(nil)
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
		setRotator(nil)
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

func setRotator(r *rotator) {
	mu.Lock()
	rot = r
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
