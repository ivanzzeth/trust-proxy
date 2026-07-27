package gateway

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
)

// A change that builds but fails to start must leave the gateway running.
//
// rebuild() closes the old box before starting the new one — deliberately, since
// they want the same ports. A *build* failure is therefore safe: it returns before
// anything is closed. A *start* failure was not: m.instance was already nil, the
// old box already closed, and nothing brought either back. The gateway had no
// running box at all until some later rebuild happened to succeed, and the log line
// admitting it ("gateway has no running box until the next successful rebuild") was
// the whole recovery story.
//
// It matters because start failures are not exotic. Everything that reaches out
// during startup fails there: a remote rule set whose source is unreachable is
// fatal at initial load, which is the scenario two of this session's bugs were
// about. So the most likely way to lose the data plane entirely was to apply a
// policy referencing something the machine could not fetch.
//
// The fix keeps the last configuration that actually started and restores it. The
// requested change still fails — the caller is told, and its own revert path fixes
// the stores — but the machine keeps forwarding traffic under the previous policy
// instead of forwarding nothing.
func TestAFailedStartKeepsThePreviousDataPlane(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfgPath := filepath.Join(dir, "config.json")
	writeBase(t, cfgPath, port)

	engine := detect.New(64)
	mgr := NewManager(cfgPath, dir, whitelist.Rules{Domains: []string{"example.com"}}, engine, "", "")
	if err := mgr.Start(); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if !accepts(port) {
		t.Fatal("the gateway is not listening after a successful start; nothing below would mean anything")
	}

	// Make the *base config* unstartable behind the manager's back: an inbound on a
	// port somebody else holds. rebuild() re-reads this file every time, so from here
	// on both the requested change and the revert of it produce a config that builds
	// and refuses to start.
	//
	// That is the case the callers' revert cannot cover, and it is reachable without
	// anything exotic: hand-edit config.json, or point -c at a file somebody else
	// manages, then change any policy. The revert reported success — "apply X failed
	// (reverted)" — while the gateway was down, so the message actively said the
	// opposite of what had happened.
	taken := occupy(t)
	writeBase(t, cfgPath, taken)

	err := mgr.SetWhitelist(whitelist.Rules{Domains: []string{"example.com", "other.example"}})
	if err == nil {
		t.Fatal("applying a policy on top of an unstartable base config reported success")
	}
	// The error has to say the gateway was restored, or say it is down — what it must
	// not do is claim a clean revert while nothing is running.
	if !strings.Contains(err.Error(), "restored") && !strings.Contains(err.Error(), "not running") {
		t.Errorf("the error says neither that the previous config was restored nor that the "+
			"gateway is down: %q", err)
	}

	// The claim: still forwarding, on the last configuration that actually started.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if accepts(port) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the gateway stopped listening on %d: a policy change that could not be applied, "+
		"on top of a base config that could not start, took the data plane down (error: %v)", port, err)
}

// Repeatedly, and the restore must keep working — it has to be the last config that
// *started*, not the last one attempted, or the second failure has nothing good left.
func TestRestoreUsesTheLastConfigThatActuallyStarted(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfgPath := filepath.Join(dir, "config.json")
	writeBase(t, cfgPath, port)

	engine := detect.New(64)
	mgr := NewManager(cfgPath, dir, whitelist.Rules{Domains: []string{"example.com"}}, engine, "", "")
	if err := mgr.Start(); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	taken := occupy(t)
	writeBase(t, cfgPath, taken)

	for i := 0; i < 3; i++ {
		if err := mgr.SetWhitelist(whitelist.Rules{
			Domains: []string{"example.com", fmt.Sprintf("try-%d.example", i)},
		}); err == nil {
			t.Fatalf("attempt %d reported success on an unstartable base config", i)
		}
		if !waitAccepts(port) {
			t.Fatalf("the gateway is down after failure %d", i)
		}
	}
}

// writeBase writes a minimal, valid gateway config listening on port.
func writeBase(t *testing.T, path string, port int) {
	t.Helper()
	cfg := fmt.Sprintf(`{
	  "inbounds": [{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":%d}],
	  "outbounds": [{"type":"direct","tag":"direct"},{"type":"block","tag":"blocked"},
	                {"type":"selector","tag":"proxy","outbounds":["direct"]}],
	  "route": {"rules": [{"action":"sniff"},
	                      {"network":["tcp","udp"],"action":"route","outbound":"blocked"}],
	            "final":"blocked"}
	}`, port)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// occupy holds a port for the duration of the test and returns it, so a config
// naming it builds and cannot start.
func occupy(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

func waitAccepts(port int) bool {
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if accepts(port) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// freePort reserves and releases a port, so the config can name one nothing is
// using. Racy in principle; in a test binary that is the accepted trade for not
// hardcoding ports that collide with a developer's running gateway.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func accepts(port int) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
