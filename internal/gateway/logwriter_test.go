package gateway

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
)

// syncBuffer is a writer the box may hit from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// sing-box logs one line per connection from the connection goroutine, so its
// writer must be ours (the async ring) — not a file, and not stderr. This asserts
// the box.Options.DefaultLogWriter wiring end to end: start a real box and check
// its own startup lines arrive in our sink.
func TestSingBoxLogsGoToOurWriter(t *testing.T) {
	dir := t.TempDir()
	cfg := dir + "/config.json"
	// Same shape as baseCfg but with a log block: level info, no output path (so
	// DefaultLogWriter applies) and free ports.
	writeFile(t, cfg, `{
	  "log": {"level": "info", "timestamp": true},
	  "inbounds": [{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":0}],
	  "outbounds": [{"type":"direct","tag":"direct"},{"type":"block","tag":"blocked"},{"type":"selector","tag":"proxy","outbounds":["direct"]}],
	  "route": {"rules": [{"action":"sniff"},{"network":["tcp","udp"],"action":"route","outbound":"blocked"}], "final":"blocked"}
	}`)

	sink := &syncBuffer{}
	mgr := NewManager(cfg, dir, whitelist.Rules{}, detect.New(16), "")
	mgr.SetLogWriter(sink)
	if err := mgr.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer mgr.Close()

	out := sink.String()
	if !strings.Contains(out, "sing-box started") {
		t.Fatalf("sing-box logs did not reach our writer, got: %q", out)
	}
	// A supplied writer is not a terminal: the fork disables colors, so lines
	// land as plain text instead of the ANSI soup the old file logs carried.
	if strings.Contains(out, "\x1b[") {
		t.Fatalf("expected colorless output for an injected writer, got: %q", out)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
