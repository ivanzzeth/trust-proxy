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
		time.Sleep(10 * time.Second)
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
		time.Sleep(10 * time.Second)
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
