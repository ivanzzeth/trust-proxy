package detect

import (
	"net"
	"sync"
	"sync/atomic"
)

// Wrap returns conn wrapped so bytes are counted into ev. Read (bytes from the
// client, heading out) counts as upload; Write (bytes back to the client) as
// download. finalize() runs once on Close.
func (e *Engine) Wrap(conn net.Conn, ev *Event) net.Conn {
	return &countConn{Conn: conn, ev: ev, engine: e}
}

type countConn struct {
	net.Conn
	ev     *Event
	engine *Engine
	once   sync.Once
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddInt64(&c.ev.Upload, int64(n))
	}
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddInt64(&c.ev.Download, int64(n))
	}
	return n, err
}

func (c *countConn) Close() error {
	c.once.Do(func() { c.engine.finalize(c.ev) })
	return c.Conn.Close()
}
