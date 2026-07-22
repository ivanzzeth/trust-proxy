package gateway

import (
	"context"
	"net"

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

var _ adapter.ConnectionTracker = (*detector)(nil)

func (d *detector) RoutedConnection(ctx context.Context, conn net.Conn, m adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	ev := d.engine.Track("tcp", host(m), m.Destination.String(), m.Source.String(), procOf(m), ruleStr(matchedRule), outStr(matchOutbound))
	return d.engine.Wrap(conn, ev)
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
