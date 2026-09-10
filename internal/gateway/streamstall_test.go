package gateway

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
)

type progressConn struct{}

func (progressConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	b[0] = 1
	return 1, nil
}
func (progressConn) Write(b []byte) (int, error)      { return len(b), nil }
func (progressConn) Close() error                     { return nil }
func (progressConn) LocalAddr() net.Addr              { return nil }
func (progressConn) RemoteAddr() net.Addr             { return nil }
func (progressConn) SetDeadline(time.Time) error      { return nil }
func (progressConn) SetReadDeadline(time.Time) error  { return nil }
func (progressConn) SetWriteDeadline(time.Time) error { return nil }

// eofConn is a connection whose read fails, i.e. one that ended.
type eofConn struct{ progressConn }

func (eofConn) Read([]byte) (int, error) { return 0, io.EOF }

// countingConn records whether the sweeper closed it. That is what separates a
// kill (we close the conn and demote the member) from a drop (we stop watching
// a connection that ended on its own) — both remove it from the watch set, so
// the set size cannot tell them apart.
type countingConn struct {
	progressConn
	eof    bool
	closes atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	if c.eof {
		return 0, io.EOF
	}
	return c.progressConn.Read(b)
}

func (c *countingConn) Close() error {
	c.closes.Add(1)
	return nil
}

func TestIsProxyMemberOutbound(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want bool
	}{
		{"🇭🇰 Hong Kong丨02", true},
		{"anytls/🇭🇰 Hong Kong丨02", true},
		{"direct", false},
		{"Direct", false},
		{"block", false},
		{"blocked", false},
		{"direct/direct", false},
		{"", false},
	} {
		if got := isProxyMemberOutbound(tc.out); got != tc.want {
			t.Errorf("isProxyMemberOutbound(%q)=%v, want %v", tc.out, got, tc.want)
		}
	}
}

func TestStallConn_ShouldKill(t *testing.T) {
	ev := &detect.Event{}
	atomic.StoreInt64(&ev.Upload, 100_000)
	c := &stallConn{
		ev:        ev,
		minUpload: 64 * 1024,
		minAge:    time.Second,
		stallFor:  2 * time.Second,
		started:   time.Now().Add(-time.Minute),
	}
	atomic.StoreInt64(&c.lastDownUnix, time.Now().Add(-3*time.Second).UnixNano())
	if !c.shouldKill() {
		t.Fatal("large upload + download silence should kill")
	}

	atomic.StoreInt64(&c.lastDownUnix, time.Now().UnixNano())
	if c.shouldKill() {
		t.Fatal("recent download must not kill")
	}

	atomic.StoreInt64(&c.lastDownUnix, time.Now().Add(-3*time.Second).UnixNano())
	atomic.StoreInt64(&ev.Upload, 1024)
	if c.shouldKill() {
		t.Fatal("below min upload must not kill")
	}

	atomic.StoreInt64(&ev.Upload, 100_000)
	c.started = time.Now()
	c.minAge = time.Minute
	if c.shouldKill() {
		t.Fatal("young connection must not kill")
	}
}

func TestStallConn_OnlyDownloadRefreshesSilenceClock(t *testing.T) {
	c := &stallConn{Conn: progressConn{}}
	old := time.Now().Add(-time.Minute).UnixNano()
	atomic.StoreInt64(&c.lastDownUnix, old)

	if _, err := c.Write([]byte("upload")); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&c.lastDownUnix); got != old {
		t.Fatalf("upload refreshed download clock: got %d want %d", got, old)
	}

	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&c.lastDownUnix); got <= old {
		t.Fatalf("download did not refresh silence clock: got %d, old %d", got, old)
	}
}

// The sweeper replaced one goroutine + one 1Hz ticker per connection. sweep()
// is called directly here so the assertions are about what it decides, not
// about when a timer happened to fire.
func TestStallSweeper_DropsFinishedAndKillsStalled(t *testing.T) {
	m := &Manager{}
	w := m.stallSweeper()

	raw := &countingConn{}
	stalled := &stallConn{Conn: raw, ev: &detect.Event{Outbound: "anytls/node-a", Upload: 1 << 20}}
	stalled.started = time.Now().Add(-time.Minute)
	stalled.minUpload = 1 << 10
	stalled.stallFor = time.Second
	atomic.StoreInt64(&stalled.lastDownUnix, time.Now().Add(-time.Minute).UnixNano())
	stalled.mgr = m

	closed := &stallConn{Conn: progressConn{}, ev: &detect.Event{Outbound: "anytls/node-b"}, mgr: m}
	closed.finished.Store(true)

	healthy := &stallConn{Conn: progressConn{}, ev: &detect.Event{Outbound: "anytls/node-c"}, mgr: m}
	healthy.started = time.Now()
	healthy.minUpload = 1 << 10
	healthy.stallFor = time.Minute
	atomic.StoreInt64(&healthy.lastDownUnix, time.Now().UnixNano())

	w.add(stalled)
	w.add(closed)
	w.add(healthy)

	if left := w.sweep(); left != 1 {
		t.Fatalf("after one sweep %d connections are still watched, want 1 (only the healthy one)", left)
	}
	if !stalled.finished.Load() {
		t.Fatal("stalled connection was not killed")
	}
	if healthy.finished.Load() {
		t.Fatal("healthy connection was killed")
	}
	if n := raw.closes.Load(); n != 1 {
		t.Fatalf("stalled connection closed %d times, want exactly 1", n)
	}
}

// A read error — EOF included — ends the watch. Without this the silence after
// a connection simply finished looks exactly like a stall, so the sweeper closes
// it again and demotes the member for a connection that ended normally.
func TestStallConn_ReadErrorEndsTheWatchInsteadOfDemoting(t *testing.T) {
	m := &Manager{}
	w := m.stallSweeper()

	raw := &countingConn{eof: true}
	c := &stallConn{Conn: raw, ev: &detect.Event{Outbound: "anytls/node-a", Upload: 1 << 20}, mgr: m}
	c.started = time.Now().Add(-time.Minute)
	c.minUpload = 1 << 10
	c.stallFor = time.Second
	atomic.StoreInt64(&c.lastDownUnix, time.Now().Add(-time.Minute).UnixNano())

	// Before the read it matches the stall shape exactly.
	if !c.shouldKill() {
		t.Fatal("precondition: this connection should match the stall shape")
	}
	w.add(c)
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the read to fail")
	}
	if left := w.sweep(); left != 0 {
		t.Fatalf("%d connections still watched after the read failed, want 0", left)
	}
	if n := raw.closes.Load(); n != 0 {
		t.Fatalf("sweeper closed a connection that had already ended (%d closes) — that path also demotes the member", n)
	}
}

// The sweeper's goroutine must stop when the last watched connection goes, so an
// idle gateway holds no timer, and start again on the next wrap.
func TestStallSweeper_StopsWhenEmptyAndRestarts(t *testing.T) {
	m := &Manager{}
	w := m.stallSweeper()

	c := &stallConn{Conn: progressConn{}, ev: &detect.Event{Outbound: "anytls/node-a"}, mgr: m}
	c.finished.Store(true)
	w.add(c)

	w.mu.Lock()
	running := w.running
	w.mu.Unlock()
	if !running {
		t.Fatal("add did not start the sweeper")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		w.mu.Lock()
		running = w.running
		n := len(w.conns)
		w.mu.Unlock()
		if !running && n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sweeper still running with %d connections watched", n)
		}
		time.Sleep(50 * time.Millisecond)
	}

	w.add(&stallConn{Conn: progressConn{}, ev: &detect.Event{Outbound: "anytls/node-b"}, mgr: m})
	w.mu.Lock()
	running = w.running
	w.mu.Unlock()
	if !running {
		t.Fatal("sweeper did not restart for a new connection")
	}
}
