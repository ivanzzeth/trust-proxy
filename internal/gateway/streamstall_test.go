package gateway

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
)

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
