package history

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	t.Cleanup(func() { _ = s.Close() })

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

func TestRecentPage_IncludesRotatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	s.Record(detect.Event{
		Time: time.Unix(1700000000, 0).Format(time.RFC3339),
		Host: "old.example", Destination: "1.1.1.1:443", Outbound: "direct",
		Upload: 1, Download: 1,
	})

	// Force a rotation the way Record() would on size overflow, without writing
	// tens of MiB: lumberjack rotates on demand.
	s.mu.Lock()
	if err := s.w.Rotate(); err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()

	s.Record(detect.Event{
		Time: time.Unix(1700000100, 0).Format(time.RFC3339),
		Host: "new.example", Destination: "2.2.2.2:443", Outbound: "proxy",
		Upload: 1, Download: 1,
	})

	items, total := s.RecentPage(10, 0, "")
	if total != 2 {
		t.Fatalf("expected both pre- and post-rotation records reachable, total=%d items=%v", total, items)
	}
	if items[0].Host != "new.example" || items[1].Host != "old.example" {
		t.Fatalf("expected newest-first across the rotation boundary, got %v", items)
	}
}

// History used to grow to ~128 MiB (64 MiB live + one uncompressed rename) with
// no age bound, and startup replays the live file — so the cap has to hold and
// old generations have to be reaped, not just renamed once.
func TestRetentionBoundsTheFileAndKeepsBrowsingRotatedData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	s, err := NewStoreWithOptions(path, Options{MaxSizeMB: 1, MaxBackups: 2, Compress: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	pad := strings.Repeat("x", 900) // ~1 KiB per record
	for i := 0; i < 4500; i++ {     // ~4.4 MiB => several rotations
		s.Record(detect.Event{
			Time: time.Unix(int64(1700000000+i), 0).Format(time.RFC3339),
			Host: "h" + pad, Destination: "1.1.1.1:443", Outbound: "direct", Upload: 1, Download: 1,
		})
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 2<<20 {
		t.Fatalf("live history is %d bytes, want it bounded near the 1 MiB cap", fi.Size())
	}
	// Compression and reaping run after the rename, so allow the mill to settle
	// before asserting the bound.
	var names []string
	for i := 0; i < 100; i++ {
		entries, _ := os.ReadDir(dir)
		names = names[:0]
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if len(names) <= 3 { // live + MaxBackups
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(names) > 3 {
		t.Fatalf("MaxBackups=2 exceeded after settling: %v", names)
	}

	// Compressed generations must still be browsable, or turning compression on
	// silently shrinks what the History page can show.
	if _, total := s.RecentPage(10, 0, ""); total <= 1 {
		t.Fatalf("rotated (gzipped) records unreachable: total=%d", total)
	}
}

// The console polls history every 5s. RecentPage used to parse every record in
// every generation per call — ~300ms and a full multi-MB read on a real box, for
// 50 rows. An unfiltered page must decode its own window, not the corpus.
func TestUnfilteredPageDoesNotDecodeTheWholeHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	const records = 20000
	for i := 0; i < records; i++ {
		s.Record(detect.Event{
			Time: time.Unix(int64(1700000000+i), 0).Format(time.RFC3339),
			Host: fmt.Sprintf("h%05d.example", i), Destination: "1.1.1.1:443",
			Process: "curl", Outbound: "direct", Upload: 1, Download: 1,
		})
	}

	s.readMu.Lock()
	s.parsed = 0
	s.readMu.Unlock()

	items, total := s.RecentPage(50, 0, "")
	if total != records {
		t.Fatalf("total = %d, want %d", total, records)
	}
	if len(items) != 50 {
		t.Fatalf("got %d rows, want 50", len(items))
	}
	// Newest first, and it really is the newest.
	if items[0].Host != fmt.Sprintf("h%05d.example", records-1) {
		t.Fatalf("first row = %s, want the newest record", items[0].Host)
	}
	s.readMu.Lock()
	parsed := s.parsed
	s.readMu.Unlock()
	if parsed > 500 { // one tail chunk's worth, not 20k
		t.Fatalf("decoded %d records to serve 50 rows", parsed)
	}
}

// Deep paging still works: an offset past the tail window walks further back,
// and the ordering stays chronological across the boundary.
func TestDeepOffsetStillPagesCorrectly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	const records = 5000
	for i := 0; i < records; i++ {
		s.Record(detect.Event{
			Time: time.Unix(int64(1700000000+i), 0).Format(time.RFC3339),
			Host: fmt.Sprintf("h%05d.example", i), Destination: "1.1.1.1:443", Outbound: "direct",
		})
	}
	items, total := s.RecentPage(10, 4000, "")
	if total != records {
		t.Fatalf("total = %d, want %d", total, records)
	}
	if len(items) != 10 {
		t.Fatalf("got %d rows", len(items))
	}
	// offset 4000 from the newest end => record index records-1-4000.
	if want := fmt.Sprintf("h%05d.example", records-1-4000); items[0].Host != want {
		t.Fatalf("first row at offset 4000 = %s, want %s", items[0].Host, want)
	}
}

// A filtered page reports the true match count and decodes only candidates.
func TestFilteredPageCountsMatchesWithoutDecodingEverything(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	for i := 0; i < 3000; i++ {
		host := "noise.example"
		if i%100 == 0 {
			host = "needle.example"
		}
		s.Record(detect.Event{
			Time: time.Unix(int64(1700000000+i), 0).Format(time.RFC3339),
			Host: host, Destination: "1.1.1.1:443", Outbound: "direct",
		})
	}
	s.readMu.Lock()
	s.parsed = 0
	s.readMu.Unlock()

	items, total := s.RecentPage(10, 0, "needle")
	if total != 30 {
		t.Fatalf("total = %d, want 30 matches", total)
	}
	if len(items) != 10 || items[0].Host != "needle.example" {
		t.Fatalf("items = %d, first = %q", len(items), items[0].Host)
	}
	s.readMu.Lock()
	parsed := s.parsed
	s.readMu.Unlock()
	if parsed > 100 { // only candidate lines get decoded, not all 3000
		t.Fatalf("decoded %d records for 30 matches", parsed)
	}
}
