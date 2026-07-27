package api

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/authn"
	"github.com/ivanzzeth/trust-proxy/internal/users"
)

// Unauthenticated password verification is a memory amplifier.
//
// POST /api/auth/login is public and each attempt forces a 19 MiB, t=2 argon2id
// derivation — deliberately, even for a username that does not exist, so an
// unknown account and a wrong password take the same time. That constant-time
// property is worth keeping and it means an anonymous caller controls a 19 MiB
// allocation. Enough of them at once and the machine runs out, which on this
// process does not merely break the API: it takes the data plane down with it,
// because they are the same binary. There was no limiter, lockout or delay
// anywhere.
//
// Two independent limits, because they answer different questions. The semaphore
// bounds how much memory can be in flight at once, whatever the arrival rate. The
// per-client rate limit bounds how many guesses an attacker gets, whatever the
// concurrency.

func TestLoginConcurrencyIsBounded(t *testing.T) {
	th := newThrottle(2, 100, time.Minute)

	var held []func()
	for i := 0; i < 2; i++ {
		release, ok := th.acquire()
		if !ok {
			t.Fatalf("slot %d refused while under the limit", i)
		}
		held = append(held, release)
	}
	if _, ok := th.acquire(); ok {
		t.Fatal("a third concurrent verification was admitted: an anonymous caller can hold " +
			"an unbounded amount of argon2 memory at once")
	}
	held[0]()
	release, ok := th.acquire()
	if !ok {
		t.Fatal("a slot did not free up after release")
	}
	release()
	held[1]()
}

func TestLoginRateIsLimitedPerClient(t *testing.T) {
	th := newThrottle(8, 3, time.Minute)

	for i := 0; i < 3; i++ {
		if !th.allow("10.0.0.1") {
			t.Fatalf("attempt %d refused while under the limit", i+1)
		}
	}
	if th.allow("10.0.0.1") {
		t.Fatal("a fourth attempt was allowed: password guessing is unbounded")
	}
	// A different client is unaffected — one noisy source must not lock everyone
	// else out of their own gateway.
	if !th.allow("10.0.0.2") {
		t.Fatal("one client's attempts exhausted another client's budget")
	}
}

// The window has to actually roll, or the limit is a permanent lockout — which is
// its own denial of service, and worse on a gateway nobody can log in to fix.
func TestRateWindowRolls(t *testing.T) {
	th := newThrottle(8, 1, 50*time.Millisecond)
	if !th.allow("10.0.0.3") {
		t.Fatal("first attempt refused")
	}
	if th.allow("10.0.0.3") {
		t.Fatal("second attempt inside the window was allowed")
	}
	time.Sleep(80 * time.Millisecond)
	if !th.allow("10.0.0.3") {
		t.Fatal("the window never rolled, so this is a permanent lockout")
	}
}

// Bookkeeping must not grow without bound either: an attacker spraying from many
// source addresses would otherwise turn the limiter itself into the memory leak
// it exists to prevent.
func TestThrottleForgetsIdleClients(t *testing.T) {
	th := newThrottle(8, 1, 20*time.Millisecond)
	for i := 0; i < 200; i++ {
		th.allow(fmt.Sprintf("10.1.%d.%d", i/256, i%256))
	}
	time.Sleep(60 * time.Millisecond)
	th.allow("10.2.0.1") // any call triggers the sweep
	if n := th.size(); n > 16 {
		t.Fatalf("the limiter is holding %d expired clients", n)
	}
}

// End to end through the handler: the fourth attempt from one address is refused
// with 429 rather than costing another derivation.
func TestLoginHandlerRefusesAFlood(t *testing.T) {
	s, us, _, _ := newAuthServer(t)
	if _, err := us.Create("admin", "admin-password-long", users.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	s.throttle = newThrottle(4, 3, time.Minute)

	var codes []int
	for i := 0; i < 5; i++ {
		r := req("POST", "/api/auth/login")
		r.RemoteAddr = "203.0.113.9:5000"
		codes = append(codes, serve(s, r).Code)
	}
	if codes[len(codes)-1] != http.StatusTooManyRequests {
		t.Fatalf("attempt 5 returned %d, want 429 (codes: %v)", codes[len(codes)-1], codes)
	}
	// A different source is still served, so the limiter cannot be used to lock the
	// owner out of their own gateway.
	r := req("POST", "/api/auth/login")
	r.RemoteAddr = "203.0.113.10:5000"
	if got := serve(s, r).Code; got == http.StatusTooManyRequests {
		t.Fatal("one flooding source locked out every other client")
	}
}

// The limiter guards the expensive public endpoints and nothing else: an
// authenticated admin driving the CLI in a loop must not be throttled by the same
// counter as an anonymous password guesser.
func TestThrottleDoesNotApplyToAuthenticatedRoutes(t *testing.T) {
	s, us, a, _ := newAuthServer(t)
	admin, err := us.Create("admin", "admin-password-long", users.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, _ := a.Issue(admin)
	s.throttle = newThrottle(4, 2, time.Minute)

	for i := 0; i < 10; i++ {
		r := req("GET", "/api/status")
		r.RemoteAddr = "203.0.113.11:5000"
		r.AddCookie(&http.Cookie{Name: authn.CookieName, Value: tok})
		if got := serve(s, r).Code; got != 200 {
			t.Fatalf("authenticated read %d returned %d", i, got)
		}
	}
}

// Concurrent acquire/release must not race. Run with -race in CI.
func TestThrottleIsConcurrencySafe(t *testing.T) {
	th := newThrottle(4, 1000, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			th.allow(fmt.Sprintf("10.3.0.%d", i%8))
			if release, ok := th.acquire(); ok {
				release()
			}
		}(i)
	}
	wg.Wait()
}
