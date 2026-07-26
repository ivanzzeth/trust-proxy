package detect

import "time"

// Kind classifies a detection finding.
type Kind string

const (
	KindIntel  Kind = "intel"
	KindExfil  Kind = "exfil"
	KindBeacon Kind = "beacon"
	KindDGA    Kind = "dga"
	// KindDNS covers query-level findings: NXDOMAIN sweeps, payload-carrying
	// record types, tunnel-rate parents. Distinct from KindDGA, which scores the
	// shape of a single name.
	KindDNS Kind = "dns"
)

// Action is how the system disposed of the finding.
type Action string

const (
	ActionAlert   Action = "alert"   // logged only
	ActionBlocked Action = "blocked" // connection killed, not banned
	ActionBanned  Action = "banned"  // written to deny-list (implies kill when auto-block on)
)

// Event is one observed egress connection plus its detection verdict.
// Kept for the connection ring / history finalize sink; alerts also emit Detection.
type Event struct {
	ID          uint64   `json:"id"`
	Time        string   `json:"time"`
	Network     string   `json:"network"`
	Host        string   `json:"host"`
	Destination string   `json:"destination"`
	Source      string   `json:"source"`
	Process     string   `json:"process"`
	Rule        string   `json:"rule"`
	Outbound    string   `json:"outbound"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	Level       string   `json:"level"`            // "info" | "alert"
	Block       bool     `json:"block,omitempty"`  // auto-block eligible
	Denied      bool     `json:"denied,omitempty"` // routed to block outbound
	Reasons     []string `json:"reasons,omitempty"`
	// DurationMS is how long the connection was open (set once it closes; 0
	// while still active). The single most useful signal for "why does this
	// feel slow" — a long duration with few bytes moved means the connection
	// stalled somewhere, not that it moved a lot of data.
	DurationMS int64 `json:"duration_ms,omitempty"`
	// DNSMs/ConnectMs/TLSMs break DurationMS down into phases, when a
	// TimingSource was attached (see SetTiming) and the gateway's underlying
	// dial actually went through each phase:
	//   DNSMs     - resolving the hostname (0 if the destination was a literal IP)
	//   ConnectMs - establishing the transport connection (TCP, and TLS too
	//               when the outbound doesn't separately report a TLS phase —
	//               see TLSMs)
	//   TLSMs     - the TLS handshake, when reported separately (vless/vmess/
	//               trojan/anytls; 0 for non-TLS outbounds and QUIC-based
	//               protocols, whose handshake isn't a separable phase)
	// All 0 when no TimingSource was ever attached (e.g. UDP). There's no
	// time-to-first-byte phase: getting it would require wrapping the
	// destination conn all the way into the data-copy path, which broke a
	// copy-loop fast path for at least shadowsocks2's AEAD-2022 client (a
	// real, reproducible data race) — not worth it for one more metric.
	DNSMs     int64 `json:"dns_ms,omitempty"`
	ConnectMs int64 `json:"connect_ms,omitempty"`
	TLSMs     int64 `json:"tls_ms,omitempty"`

	// openedAt is when Track() created this event; write-once, read by
	// finalize() to compute DurationMS. Never mutated after Track() returns,
	// so it's safe to read without e.mu (same as Host/Destination/etc above).
	openedAt time.Time

	// timing is a write-many/read-once source of raw phase timestamps,
	// attached via SetTiming right after Track() returns. It's filled in by
	// whoever implements TimingSource (the gateway layer, reading sing-box's
	// own per-connection dial/TLS timestamps) as the connection actually
	// gets established, and read by finalize() once the connection closes.
	timing TimingSource

	// exfilEmitted avoids double Detection rows when mid-stream and finalize both see large upload.
	exfilEmitted bool
}

// TimingSource reports raw phase timestamps for one connection's dial/
// handshake. Defined here (rather than importing sing-box's adapter package
// directly) so this package stays decoupled from sing-box internals — the
// gateway layer adapts sing-box's own timing struct to this interface. A
// zero time.Time means that phase either hasn't happened yet or doesn't
// apply (e.g. DNS for an IP-literal destination, or TLS for a non-TLS
// outbound).
type TimingSource interface {
	DialStartTime() time.Time
	DNSStartTime() time.Time
	DNSDoneTime() time.Time
	TCPDoneTime() time.Time
	TLSDoneTime() time.Time
	ConnectDoneTime() time.Time
}

// SetTiming attaches a TimingSource for finalize() to read once the
// connection closes. Called by the gateway layer right after Track() returns
// (see internal/gateway/detector.go).
func (ev *Event) SetTiming(t TimingSource) { ev.timing = t }

// Detection is one alert finding (intel / exfil / beacon / dga), durable via Store.
type Detection struct {
	ID          uint64   `json:"id"`
	Time        string   `json:"time"`
	Kind        Kind     `json:"kind"`
	Host        string   `json:"host"`
	Destination string   `json:"destination"`
	Process     string   `json:"process,omitempty"`
	Upload      int64    `json:"upload,omitempty"`
	Download    int64    `json:"download,omitempty"`
	Action      Action   `json:"action"`
	Reasons     []string `json:"reasons,omitempty"`
	EventID     uint64   `json:"event_id,omitempty"`
}
