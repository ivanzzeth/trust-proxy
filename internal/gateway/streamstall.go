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
	go w.watch()
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

	lastDownUnix int64 // unix nano; updated on Write
	killed       atomic.Bool
	closeOnce    sync.Once
}

func (c *stallConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	return n, err
}

func (c *stallConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.StoreInt64(&c.lastDownUnix, time.Now().UnixNano())
	}
	return n, err
}

func (c *stallConn) Close() error {
	c.closeOnce.Do(func() { c.killed.Store(true) })
	return c.Conn.Close()
}

func (c *stallConn) watch() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for range tick.C {
		if c.killed.Load() {
			return
		}
		if !c.shouldKill() {
			continue
		}
		if !c.killed.CompareAndSwap(false, true) {
			return
		}
		c.mgr.RecordStreamStall(c.ev.Outbound)
		_ = c.Conn.Close()
		return
	}
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
	if m == nil || m.scores == nil {
		return
	}
	m.scores.RecordStreamStall(outbound)
}
