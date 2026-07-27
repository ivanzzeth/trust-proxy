package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Limits on the public endpoints that cost real resources.
//
// POST /api/auth/login is reachable by anyone who can reach the port, and each
// attempt forces a 19 MiB argon2id derivation — on purpose even for a username
// that does not exist, so that an unknown account and a wrong password take the
// same time. Keeping that property means an anonymous caller controls a 19 MiB
// allocation, and there was nothing bounding how many of those could be in flight.
// On a single-process gateway that is not an API outage: the data plane is in the
// same binary, so running the machine out of memory stops forwarding traffic.
//
// Two limits, because they bound different things:
//
//   - a semaphore on concurrent verifications caps memory in flight whatever the
//     arrival rate;
//   - a per-client attempt budget caps how many guesses an attacker gets whatever
//     the concurrency.
//
// Per-client and not global on purpose. A global attempt budget is a lockout that
// anyone can trigger for everybody, and being unable to log in to a gateway is
// exactly when you need to.
const (
	// Two at a time: enough that a human logging in never waits on somebody else,
	// low enough that the worst case is ~40 MiB rather than however many
	// connections an attacker can open.
	defaultLoginConcurrency = 2
	// Ten attempts a minute per source. A person who has forgotten their password
	// tries three or four times; a guesser needs orders of magnitude more.
	defaultLoginAttempts = 10
	defaultLoginWindow   = time.Minute
)

// throttle bounds concurrency and per-client attempt rate.
type throttle struct {
	slots  chan struct{}
	limit  int
	window time.Duration
	mu     sync.Mutex
	seen   map[string]*bucket
	lastGC time.Time
}

type bucket struct {
	count int
	reset time.Time
}

func newThrottle(concurrency, attempts int, window time.Duration) *throttle {
	return &throttle{
		slots:  make(chan struct{}, concurrency),
		limit:  attempts,
		window: window,
		seen:   map[string]*bucket{},
	}
}

// acquire takes a verification slot, or reports false when they are all busy.
//
// Non-blocking rather than queuing: a queue converts a memory problem into a
// latency problem and still lets an attacker pin every slot indefinitely. Refusing
// with 429 tells the honest caller to try again in a moment and tells the attacker
// nothing.
func (t *throttle) acquire() (release func(), ok bool) {
	if t == nil {
		return func() {}, true
	}
	select {
	case t.slots <- struct{}{}:
		return func() { <-t.slots }, true
	default:
		return nil, false
	}
}

// allow reports whether client has budget left in the current window.
func (t *throttle) allow(client string) bool {
	if t == nil {
		return true
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked(now)

	b, ok := t.seen[client]
	if !ok || now.After(b.reset) {
		t.seen[client] = &bucket{count: 1, reset: now.Add(t.window)}
		return true
	}
	if b.count >= t.limit {
		return false
	}
	b.count++
	return true
}

// gcLocked drops expired buckets. Without it, an attacker spraying from many
// source addresses turns the limiter into the memory leak it exists to prevent.
func (t *throttle) gcLocked(now time.Time) {
	if now.Sub(t.lastGC) < t.window {
		return
	}
	t.lastGC = now
	for k, b := range t.seen {
		if now.After(b.reset) {
			delete(t.seen, k)
		}
	}
}

func (t *throttle) size() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.seen)
}

// clientKey identifies the caller for rate-limiting purposes.
//
// The socket address, not a forwarded header: nothing in front of this gateway is
// trusted to set one, and honouring X-Forwarded-For here would let an attacker
// spend somebody else's budget — or an unlimited number of budgets — by making one
// up per request.
func clientKey(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// costlyPublic reports whether a request should be throttled: the public endpoints
// that do real work for an unauthenticated caller.
//
// Deliberately not everything public. /api/health and /api/auth/state are cheap
// reads the desktop shell polls, and throttling them would break the thing that
// polls them while protecting nothing.
func costlyPublic(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	switch path0(r.URL.Path) {
	case "/api/auth/login", "/api/auth/bootstrap", "/api/auth/register":
		return true
	}
	return false
}
