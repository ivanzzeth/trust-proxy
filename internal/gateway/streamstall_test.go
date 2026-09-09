package gateway

import (
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
