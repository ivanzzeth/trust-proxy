package ruleset

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A source that answers headers and then stalls must fail the probe.
//
// PickReachable asked for `Range: bytes=0-0` — one byte — on the reasoning that it
// proves the object is really there and costs nothing. The cheapness is exactly
// what made it wrong: the failure being selected against is a path that completes
// a handshake, answers a header, and then stalls partway through the body, which is
// what raw.githubusercontent.com does from inside the GFW. A one-byte range request
// is the one thing such a path can still satisfy.
//
// Measured on a real machine: every source answered HTTP 206 in under a second to a
// range request, the probe therefore kept the primary URL, and sing-box then timed
// out fetching five of thirteen rule sets from it. The mirror the catalog has always
// carried would have worked, and the probe had just voted against it.
//
// So the probe downloads the whole object. These are ~34 KB files; the cost is
// nothing and the answer is the one being asked for.
func TestPickReachableRejectsAStallingSource(t *testing.T) {
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "40000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, 512)) // a little, then nothing
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Until the client goes away, not for a fixed time: httptest.Server.Close
		// waits for outstanding handlers, so a handler that ignores cancellation makes
		// the *test* take as long as it sleeps.
		<-r.Context().Done()
	}))
	t.Cleanup(stall.Close)

	got := PickReachable([]string{stall.URL + "/geosite-cn.srs"}, 2*time.Second)
	if got != "" {
		t.Fatalf("a source that answers a header and then stalls was reported reachable (%s); "+
			"that is the exact failure the mirror exists for", got)
	}
}

// And when one source stalls while another completes, the working one wins.
func TestPickReachablePrefersTheSourceThatCompletes(t *testing.T) {
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "40000")
		_, _ = w.Write(make([]byte, 512))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	t.Cleanup(stall.Close)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 34*1024))
	}))
	t.Cleanup(good.Close)

	got := PickReachable([]string{stall.URL + "/a.srs", good.URL + "/a.srs"}, 3*time.Second)
	if got != good.URL+"/a.srs" {
		t.Fatalf("picked %q, want the source that finished", got)
	}
}

// A 404 is not reachability either — a CDN that serves an error page for a missing
// path would otherwise read as fine, and sing-box would then fail on the content.
func TestPickReachableRejectsAnErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	if got := PickReachable([]string{srv.URL + "/nope.srs"}, 2*time.Second); got != "" {
		t.Fatalf("a 404 was reported reachable: %s", got)
	}
}

// An empty 200 is not a rule set. Cheap to check and it costs a confusing failure
// later if it slips through.
func TestPickReachableRejectsAnEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	if got := PickReachable([]string{srv.URL + "/empty.srs"}, 2*time.Second); got != "" {
		t.Fatalf("an empty body was reported reachable: %s", got)
	}
}

// Nothing answering at all is the easy case, and it must not hang for the caller.
func TestPickReachableGivesUpOnADeadPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	start := time.Now()
	got := PickReachable([]string{fmt.Sprintf("http://127.0.0.1:%d/x.srs", port)}, 2*time.Second)
	if got != "" {
		t.Fatalf("a closed port was reported reachable: %s", got)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("took %s to give up on a closed port", elapsed)
	}
}

// The measured case: a source that works but at 200 bytes per second.
//
// Not a stall — it makes progress the whole way and would eventually finish. On the
// machine this came from, raw.githubusercontent.com delivered a 54 KB rule set to
// sing-box in 278 seconds while the jsdelivr mirror took 1.3, and curl fetched the
// same URL from the same host in 0.55. Same IP, same route; the difference is the
// TLS stack, which is a thing this project has already met once — the subscription
// fetcher uses uTLS with a Chrome fingerprint for exactly that reason.
//
// This is why the probe has to download the whole object rather than a byte: a
// one-byte range request completes instantly under that throttling, so the probe
// voted for the source that would take five minutes over the mirror that took one
// second. The probe runs in this process with the same TLS stack as the fetch, so
// downloading the file is a faithful measurement — it is only the range request
// that was not.
func TestPickReachableRejectsAThrottledSource(t *testing.T) {
	const size = 54 * 1024
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(size))
		w.WriteHeader(http.StatusOK)
		// ~200 B/s, which needs minutes for the whole file.
		for sent := 0; sent < size; sent += 200 {
			if _, err := w.Write(make([]byte, 200)); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}))
	t.Cleanup(slow.Close)

	start := time.Now()
	got := PickReachable([]string{slow.URL + "/geoip-cn.srs"}, 2*time.Second)
	if got != "" {
		t.Fatalf("a source delivering 200 B/s was reported reachable (%s): the fetch would take "+
			"minutes and sing-box treats a rule set it cannot load at startup as fatal", got)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the probe took %s to give up; the budget was 2s", elapsed)
	}
}

// And it picks the fast one when both are offered, which is the whole decision.
func TestPickReachablePrefersTheFastSourceOverTheThrottledOne(t *testing.T) {
	const size = 54 * 1024
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(size))
		for sent := 0; sent < size; sent += 200 {
			if _, err := w.Write(make([]byte, 200)); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}))
	t.Cleanup(slow.Close)
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, size))
	}))
	t.Cleanup(fast.Close)

	// Primary first, mirror second — the order Sources() produces, so this also pins
	// that a working mirror beats a throttled primary rather than merely tying.
	got := PickReachable([]string{slow.URL + "/a.srs", fast.URL + "/a.srs"}, 3*time.Second)
	if got != fast.URL+"/a.srs" {
		t.Fatalf("picked %q, want the source that is not throttled", got)
	}
}
