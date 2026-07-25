package history

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
)

// Proves Record() (the hot per-connection-close path) doesn't stall behind a
// concurrent RecentPage() reading a large (tens-of-MB) history file.
func TestRecordNotBlockedByLargeRecentPageRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")

	// Seed a large file (~40MB, matching the real-world size that triggered
	// this bug) directly, bypassing Record(), so NewStore's own load is fast.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	line := `{"t":"2026-07-25T12:00:00+08:00","h":"example.com","d":"example.com:443","o":"direct/direct","u":100,"dn":200}` + "\n"
	target := int64(40 << 20)
	var written int64
	for written < target {
		n, _ := f.WriteString(line)
		written += int64(n)
	}
	f.Close()

	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.RecentPage(50, 0, "")
	}()
	// Give RecentPage a moment to actually be mid-read.
	time.Sleep(5 * time.Millisecond)

	start := time.Now()
	s.Record(detect.Event{Time: time.Now().Format(time.RFC3339), Host: "test.example"})
	elapsed := time.Since(start)
	fmt.Println("Record() took", elapsed, "while a 40MB RecentPage() read was in flight")
	if elapsed > 50*time.Millisecond {
		t.Fatalf("Record() blocked for %v behind a concurrent RecentPage() read — the fix isn't working", elapsed)
	}
	<-done
}
