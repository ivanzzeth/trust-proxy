// Package detect is the detection engine: every routed (allowed) connection is
// recorded as an event, byte-counted, and scored against detection rules
// (threat-intel domain/IP match, abnormally large upload = possible exfil).
// The console reads these via /api/events.
package detect

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event is one observed egress connection plus its detection verdict.
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
	Level       string   `json:"level"` // "info" | "alert"
	Reasons     []string `json:"reasons,omitempty"`
}

// Engine holds a ring buffer of recent events and the detection config.
type Engine struct {
	mu     sync.Mutex
	events []*Event
	cap    int
	seq    uint64

	uploadAlertBytes int64
	threatDomains    map[string]struct{}
	threatIPs        map[string]struct{}
}

// New builds an engine keeping the last `capacity` events.
func New(capacity int) *Engine {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Engine{
		cap:              capacity,
		uploadAlertBytes: 10 << 20, // 10 MiB upload -> exfil alert
		threatDomains:    map[string]struct{}{},
		threatIPs:        map[string]struct{}{},
	}
}

// LoadThreats adds C2/malware indicators (domains and IPs) to match against.
func (e *Engine) LoadThreats(domains, ips []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, d := range domains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			e.threatDomains[d] = struct{}{}
		}
	}
	for _, ip := range ips {
		if ip = strings.TrimSpace(ip); ip != "" {
			e.threatIPs[ip] = struct{}{}
		}
	}
}

// SetUploadAlert sets the upload byte threshold for the exfil alert.
func (e *Engine) SetUploadAlert(bytes int64) {
	e.mu.Lock()
	e.uploadAlertBytes = bytes
	e.mu.Unlock()
}

// Track records a new connection event, runs connection-time detection, and
// returns the event (whose Upload/Download the caller updates as bytes flow).
func (e *Engine) Track(network, host, dst, src, process, rule, outbound string) *Event {
	e.mu.Lock()
	e.seq++
	ev := &Event{
		ID: e.seq, Time: time.Now().Format(time.RFC3339), Network: network,
		Host: host, Destination: dst, Source: src, Process: process, Rule: rule, Outbound: outbound,
		Level: "info",
	}
	// threat-intel match (domain + destination IP)
	if host != "" {
		if _, bad := e.threatDomains[strings.ToLower(host)]; bad {
			ev.Level = "alert"
			ev.Reasons = append(ev.Reasons, "threat-intel domain match: "+host)
		}
	}
	if ip := hostOnly(dst); ip != "" {
		if _, bad := e.threatIPs[ip]; bad {
			ev.Level = "alert"
			ev.Reasons = append(ev.Reasons, "threat-intel IP match: "+ip)
		}
	}
	e.events = append(e.events, ev)
	if len(e.events) > e.cap {
		e.events = e.events[len(e.events)-e.cap:]
	}
	e.mu.Unlock()
	return ev
}

// finalize is called when a connection closes: re-score with final byte counts.
func (e *Engine) finalize(ev *Event) {
	up := atomic.LoadInt64(&ev.Upload)
	e.mu.Lock()
	if e.uploadAlertBytes > 0 && up >= e.uploadAlertBytes {
		ev.Level = "alert"
		ev.Reasons = append(ev.Reasons, fmt.Sprintf("large upload %s (possible exfil)", humanBytes(up)))
	}
	e.mu.Unlock()
}

// Events returns a snapshot of recent events, newest first.
func (e *Engine) Events() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Event, 0, len(e.events))
	for i := len(e.events) - 1; i >= 0; i-- {
		ev := e.events[i]
		cp := *ev
		cp.Upload = atomic.LoadInt64(&ev.Upload)
		cp.Download = atomic.LoadInt64(&ev.Download)
		cp.Reasons = append([]string(nil), ev.Reasons...)
		out = append(out, cp)
	}
	return out
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func humanBytes(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10) + " B"
	}
	u := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n) / 1024
	i := 0
	for v >= 1024 && i < len(u)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, u[i])
}
