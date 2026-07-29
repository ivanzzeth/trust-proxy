package detect

import (
	"strings"
	"sync/atomic"
	"time"
)

// Exfil shaping. A byte threshold alone says "someone uploaded a lot", which on
// a developer's machine is a photo sync, a container push or an AI coding agent
// — 38 such alerts a day on the box this was tuned against. What distinguishes
// exfiltration is the *shape*: traffic that is lopsided (far more out than in),
// or bound for a destination this gateway has never seen before. Either signal
// can be switched off (set to 0), and with both off the old byte-only behaviour
// is back.

const seenMax = 8192 // bounded first-contact map

// dstKey identifies a destination for novelty tracking: prefer the domain, fall
// back to the address without its port so one host isn't "new" on every port.
func dstKey(host, destination string) string {
	if host != "" {
		return strings.ToLower(host)
	}
	return hostOnly(destination)
}

// noteSeenLocked records first contact with a destination. Caller holds e.mu.
func (e *Engine) noteSeenLocked(key string, now time.Time) {
	if key == "" {
		return
	}
	if _, ok := e.seen[key]; ok {
		return
	}
	if len(e.seen) >= seenMax {
		// Drop the oldest half rather than growing without bound. Losing old
		// entries only makes a destination look new again, which errs toward
		// alerting — the safe direction for a detector.
		cutoff := now.Add(-time.Duration(e.exfilNewDestHours) * time.Hour)
		for k, t := range e.seen {
			if t.Before(cutoff) {
				delete(e.seen, k)
			}
		}
		if len(e.seen) >= seenMax {
			for k := range e.seen { // still full: evict arbitrarily
				delete(e.seen, k)
				if len(e.seen) < seenMax/2 {
					break
				}
			}
		}
	}
	e.seen[key] = now
}

// DialedDestination reports whether this gateway has itself connected to addr.
// The host route watcher needs it: sing-box installs a /32 escape route via the
// physical interface for every destination the direct outbound dials, so without
// this every direct connection would look like a route hijack. An injected host
// route, by contrast, is for a destination we have NOT dialled — stealing future
// traffic is the whole point.
func (e *Engine) DialedDestination(ip string) bool {
	if ip == "" {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.seen[strings.ToLower(ip)]
	return ok
}

// exfilShaped reports whether a large upload also looks like exfiltration.
func (e *Engine) exfilShaped(ev *Event, up int64) bool {
	e.mu.Lock()
	minRatio := e.exfilMinRatio
	newDestHours := e.exfilNewDestHours
	first, known := e.seen[dstKey(ev.Host, ev.Destination)]
	now := e.now()
	e.mu.Unlock()

	if minRatio <= 0 && newDestHours <= 0 {
		return true // both signals disabled: byte threshold alone
	}
	if minRatio > 0 {
		down := atomic.LoadInt64(&ev.Download)
		if down <= 0 {
			return true // nothing came back at all: as lopsided as it gets
		}
		if float64(up)/float64(down) >= minRatio {
			return true
		}
	}
	if newDestHours > 0 {
		// "New" means first contact is inside the window (or we have no record).
		if !known || now.Sub(first) <= time.Duration(newDestHours)*time.Hour {
			return true
		}
	}
	return false
}

// exfilBanReason is what lands in quarantine.json / the console. Naming the
// process and destination turns "TCP connect then EOF" after a silent /32 ban
// into an operator-visible "frpc uploaded 10MB to this EIP" finding.
func exfilBanReason(ev *Event) string {
	base := "large upload to non-whitelist destination"
	if ev == nil {
		return base
	}
	var parts []string
	if ev.Process != "" {
		parts = append(parts, "process="+ev.Process)
	}
	if ev.Destination != "" {
		parts = append(parts, "dest="+ev.Destination)
	}
	if len(parts) == 0 {
		return base
	}
	return base + " (" + strings.Join(parts, ", ") + ")"
}
