package gateway

import (
	"context"
	"net"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
)

// detector implements adapter.ConnectionTracker. Attached via
// Box.Router().AppendTracker, it receives every connection the router allows
// (rejected connections are short-circuited earlier). It records each into the
// detection engine and byte-counts the TCP ones.
type detector struct {
	engine *detect.Engine
}

func newDetector(engine *detect.Engine) *detector {
	return &detector{engine: engine}
}

var (
	_ adapter.ConnectionTracker = (*detector)(nil)
	_ adapter.DNSQueryTracker   = (*detector)(nil)
)

// RoutedQuery observes every resolved DNS query (our sing-box fork's
// DNSQueryTracker). This is the only place the gateway sees names that never
// become connections — a DGA sweep is mostly NXDOMAIN, and a DNS tunnel's
// payload *is* the query stream. Runs on the resolution path, so it does a
// couple of map bumps and hands any finding to the engine's sink.
func (d *detector) RoutedQuery(ctx context.Context, message *mDNS.Msg, response *mDNS.Msg, err error) {
	if message == nil || len(message.Question) == 0 {
		return
	}
	q := message.Question[0]
	rcode := "NOERROR"
	switch {
	case err != nil:
		rcode = "SERVFAIL"
	case response != nil:
		rcode = mDNS.RcodeToString[response.Rcode]
	}
	client := ""
	if m := adapter.ContextFrom(ctx); m != nil && m.Source.IsValid() {
		client = m.Source.Addr.String()
	}
	for _, det := range d.engine.RecordQuery(client, q.Name, mDNS.TypeToString[q.Qtype], rcode) {
		d.engine.EmitDetection(det)
	}
}

func (d *detector) RoutedConnection(ctx context.Context, conn net.Conn, m adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	ev := d.engine.Track("tcp", host(m), m.Destination.String(), m.Source.String(), procOf(m), ruleStr(matchedRule), outStr(matchOutbound))
	if timing := adapter.ConnectionTimingFromContext(ctx); timing != nil {
		ev.SetTiming(connTiming{timing})
	}
	c := d.engine.Wrap(conn, ev)
	// Auto-disposal: threat-intel hits (and mid-stream exfil via Wrap) drop the
	// connection and persist the destination onto the blacklist.
	if ev.Block && d.engine.AutoBlock() {
		d.engine.BanFromEvent(ev, "threat-intel auto-block")
		_ = c.Close()
	}
	return c
}

func (d *detector) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, m adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	// UDP: record the event (no byte-count wrapper for packet conns yet).
	d.engine.Track("udp", host(m), m.Destination.String(), m.Source.String(), procOf(m), ruleStr(matchedRule), outStr(matchOutbound))
	return conn
}

// RoutedFlow is only invoked on the TUN gvisor flow path; nil is filtered out.
func (d *detector) RoutedFlow(ctx context.Context, m adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}

func host(m adapter.InboundContext) string {
	if m.Domain != "" {
		return m.Domain
	}
	return m.Destination.String()
}

func procOf(m adapter.InboundContext) string {
	if m.ProcessInfo != nil && m.ProcessInfo.ProcessPath != "" {
		return m.ProcessInfo.ProcessPath
	}
	return ""
}

func ruleStr(rule adapter.Rule) string {
	if rule != nil {
		return rule.String()
	}
	return "(final)"
}

func outStr(out adapter.Outbound) string {
	if out != nil {
		return out.Type() + "/" + out.Tag()
	}
	return ""
}

// connTiming adapts *adapter.ConnectionTiming (sing-box's raw per-connection
// phase timestamps, threaded through the router's context — see
// adapter.ConnectionTiming's doc comment in our sing-box fork) to
// detect.TimingSource, so internal/detect doesn't need to import sing-box's
// adapter package directly.
type connTiming struct{ t *adapter.ConnectionTiming }

func (c connTiming) DialStartTime() time.Time   { return c.t.DialStart }
func (c connTiming) DNSStartTime() time.Time    { return c.t.DNSStart }
func (c connTiming) DNSDoneTime() time.Time     { return c.t.DNSDone }
func (c connTiming) TCPDoneTime() time.Time     { return c.t.TCPDone }
func (c connTiming) TLSDoneTime() time.Time     { return c.t.TLSDone }
func (c connTiming) ConnectDoneTime() time.Time { return c.t.ConnectDone }
