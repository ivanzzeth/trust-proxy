package history

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
)

func TestRecentPage_OffsetAndFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.f.Close() })

	for i := 0; i < 5; i++ {
		s.Record(detect.Event{
			Time: time.Unix(int64(1700000000+i), 0).Format(time.RFC3339),
			Host: "a.example", Destination: "1.1.1.1:443", Process: "curl", Outbound: "direct",
			Upload: 1, Download: 1,
		})
	}
	s.Record(detect.Event{
		Time: time.Unix(1700000010, 0).Format(time.RFC3339),
		Host: "b.github.com", Destination: "2.2.2.2:22", Process: "ssh", Outbound: "proxy",
		Upload: 1, Download: 1,
	})

	items, total := s.RecentPage(2, 0, "")
	if total != 6 {
		t.Fatalf("total=%d want 6", total)
	}
	if len(items) != 2 {
		t.Fatalf("page len=%d want 2", len(items))
	}
	if items[0].Host != "b.github.com" {
		t.Fatalf("newest first got %q", items[0].Host)
	}

	items, total = s.RecentPage(10, 0, "github")
	if total != 1 || len(items) != 1 || items[0].Host != "b.github.com" {
		t.Fatalf("q=github got total=%d items=%v", total, items)
	}
	items, total = s.RecentPage(10, 0, "ssh")
	if total != 1 || items[0].Process != "ssh" {
		t.Fatalf("q=ssh (process) got total=%d items=%v", total, items)
	}

	items, total = s.RecentPage(2, 2, "")
	if total != 6 || len(items) != 2 {
		t.Fatalf("offset page total=%d len=%d", total, len(items))
	}
	if items[0].Host != "a.example" {
		t.Fatalf("offset page host=%q", items[0].Host)
	}

	_ = os.Remove(path)
}
