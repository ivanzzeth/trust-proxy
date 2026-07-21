package main

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
)

// detector implements adapter.ConnectionTracker. It is attached to the router
// via Box.Router().AppendTracker and therefore sits on the data path: it
// receives every connection the router *allows* (rejected connections are
// short-circuited before this point, which under our default-deny whitelist
// means the detector observes exactly the permitted egress).
//
// Milestone 1: telemetry stub. It logs each connection's metadata and returns
// the connection unchanged (pass-through). This is the seam where the
// detection engine grows next: reputation match, beaconing, abnormal upload /
// producer-consumer ratio, exfil scoring — then act (wrap-and-close here, or
// DELETE /connections/{id} via the Clash API).
type detector struct {
	logger log.Logger
}

func newDetector(logger log.Logger) *detector {
	return &detector{logger: logger}
}

var _ adapter.ConnectionTracker = (*detector)(nil)

func (d *detector) RoutedConnection(ctx context.Context, conn net.Conn, m adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	d.observe("tcp", m, matchedRule, matchOutbound)
	return conn
}

func (d *detector) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, m adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	d.observe("udp", m, matchedRule, matchOutbound)
	return conn
}

// RoutedFlow is only invoked on the TUN gvisor flow path; nil is filtered out
// by the router, so returning nil is safe while we are not running in TUN mode.
func (d *detector) RoutedFlow(ctx context.Context, m adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}

func (d *detector) observe(network string, m adapter.InboundContext, rule adapter.Rule, out adapter.Outbound) {
	host := m.Domain
	if host == "" {
		host = m.Destination.String()
	}
	proc := "-"
	if m.ProcessInfo != nil && m.ProcessInfo.ProcessPath != "" {
		proc = m.ProcessInfo.ProcessPath
	}
	ruleStr := "(final)"
	if rule != nil {
		ruleStr = rule.String()
	}
	outStr := "-"
	if out != nil {
		outStr = out.Type() + "/" + out.Tag()
	}
	d.logger.Info("[detector] allow ", network,
		" host=", host,
		" dst=", m.Destination.String(),
		" src=", m.Source.String(),
		" proto=", m.Protocol,
		" proc=", proc,
		" rule=", ruleStr,
		" out=", outStr,
	)
}
