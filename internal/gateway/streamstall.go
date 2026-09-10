package gateway

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
)

// wrapStreamStall watches a proxied connection for the "big upload, then
// silence" shape that scoring cannot see until finalize — and by then the
// IDE has already hung. When the silence window elapses it closes the conn
// and demotes the member so the client's retry picks someone else.
func (m *Manager) wrapStreamStall(conn net.Conn, ev *detect.Event) net.Conn {
	if m == nil || m.scores == nil || ev == nil || !isProxyMemberOutbound(ev.Outbound) {
		return conn
	}
	cfg := m.scores.Config()
	stallSec := cfg.StreamStall()
	if stallSec <= 0 || cfg.Disabled {
		return conn
	}
	w := &stallConn{
		Conn:      conn,
		ev:        ev,
		mgr:       m,
		minUpload: int64(cfg.StallMinUpload()),
		minAge:    time.Duration(cfg.StallMinAge()) * time.Second,
		stallFor:  time.Duration(stallSec) * time.Second,
		started:   time.Now(),
	}
	atomic.StoreInt64(&w.lastDownUnix, time.Now().UnixNano())
	m.stallSweeper().add(w)
	return w
}

func isProxyMemberOutbound(outbound string) bool {
	o := strings.ToLower(strings.TrimSpace(outbound))
	if o == "" || o == "direct" || o == "block" || o == "blocked" || o == "dns-direct" {
		return false
	}
	if strings.HasPrefix(o, "direct/") || strings.HasPrefix(o, "block/") {
		return false
	}
	return true
}

type stallConn struct {
	net.Conn
	ev        *detect.Event
	mgr       *Manager
	minUpload int64
	minAge    time.Duration
	stallFor  time.Duration
	started   time.Time

	lastDownUnix int64 // unix nano; updated when remote download bytes arrive
	// finished means "stop watching this connection": it was closed, it failed,
	// or we killed it. Never demote a member on a finished connection.
	finished atomic.Bool
}

func (c *stallConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.StoreInt64(&c.lastDownUnix, time.Now().UnixNano())
	}
	if err != nil {
		// The shape we hunt is a read that never returns, not one that fails.
		// Once it has failed there is nothing left to wait for, and counting
		// the silence afterwards would demote the member for a connection that
		// merely ended — EOF included.
		c.finished.Store(true)
	}
	return n, err
}

func (c *stallConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

func (c *stallConn) Close() error {
	c.finished.Store(true)
	return c.Conn.Close()
}

// stallSweeper watches every wrapped connection from one goroutine.
//
// This was a goroutine and a 1s ticker per connection. The per-tick cost was
// never the point — a timer fire is cheap — the lifetime was: the watcher
// learned a connection was over only on its next tick, and only when Close()
// came through the wrapper, so a connection that ended any other way kept its
// goroutine and its 1Hz timer for the life of the process. Long-lived idle
// streams are the normal case rather than the edge (on a live gateway the
// oldest proxied connection was 9.8 hours old: ~35k wakeups to decide nothing),
// and each of those tickers also held the Event and the conn from being freed.
type stallSweeper struct {
	mu      sync.Mutex
	conns   map[*stallConn]struct{}
	running bool
}

// stallSweeper returns the manager's sweeper, creating it on first use.
func (m *Manager) stallSweeper() *stallSweeper {
	m.stallOnce.Do(func() { m.stalls = &stallSweeper{conns: map[*stallConn]struct{}{}} })
	return m.stalls
}

func (w *stallSweeper) add(c *stallConn) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.conns[c] = struct{}{}
	if w.running {
		return
	}
	// Started on demand and stopped when the last watched connection goes, so
	// an idle gateway holds no timer at all.
	w.running = true
	go w.run()
}

func (w *stallSweeper) run() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for range tick.C {
		if w.sweep() == 0 {
			w.mu.Lock()
			// Re-check under the lock: add() may have arrived between the sweep
			// and here, and it only starts a goroutine when running is false.
			if len(w.conns) == 0 {
				w.running = false
				w.mu.Unlock()
				return
			}
			w.mu.Unlock()
		}
	}
}

// sweep evaluates every watched connection and returns how many are left.
func (w *stallSweeper) sweep() int {
	w.mu.Lock()
	live := make([]*stallConn, 0, len(w.conns))
	for c := range w.conns {
		live = append(live, c)
	}
	w.mu.Unlock()

	var kill []*stallConn
	var drop []*stallConn
	for _, c := range live {
		if c.finished.Load() {
			drop = append(drop, c)
			continue
		}
		if c.shouldKill() {
			kill = append(kill, c)
		}
	}
	// Close outside the lock: Close() runs user code down the conn chain.
	for _, c := range kill {
		if !c.finished.CompareAndSwap(false, true) {
			continue
		}
		c.mgr.RecordStreamStall(c.ev.Outbound)
		_ = c.Conn.Close()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range drop {
		delete(w.conns, c)
	}
	for _, c := range kill {
		delete(w.conns, c)
	}
	return len(w.conns)
}

func (c *stallConn) shouldKill() bool {
	if time.Since(c.started) < c.minAge {
		return false
	}
	up := atomic.LoadInt64(&c.ev.Upload)
	if up < c.minUpload {
		return false
	}
	last := time.Unix(0, atomic.LoadInt64(&c.lastDownUnix))
	// No download progress at all since wrap, or stalled after some download.
	if time.Since(last) < c.stallFor {
		return false
	}
	// Still getting download? lastDown would be recent. Require the silence.
	// Avoid killing healthy uploads that simply haven't received a reply yet
	// for less than stallFor — already gated above.
	dn := atomic.LoadInt64(&c.ev.Download)
	// If download is keeping up with upload (ratio ok), don't kill even on
	// a quiet period after a burst — but our lastDown check already covers
	// "any recent download byte". Silence + big upload is enough; requiring
	// dn==0 would miss the Cursor-agent shape (a few KiB then death).
	_ = dn
	return true
}

// RecordStreamStall demotes a member after a mid-connection stall kill so the
// next Select prefers someone else. Same breaker force-open as blackhole —
// conclusive evidence, no waiting for BreakerFailures more samples.
func (m *Manager) RecordStreamStall(outbound string) {
	// scorableMember: a stall kill names whatever the connection was routed to,
	// which right after a rebuild can be a group rather than a member. See
	// Manager.scorableMember.
	if m == nil || m.scores == nil || !m.scorableMember(outbound) {
		return
	}
	m.scores.RecordStreamStall(outbound)
}
