package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
)

func fill(t *testing.T, s *Store, n int) {
	t.Helper()
	pad := strings.Repeat("x", 900) // ~1 KiB per record
	for i := 0; i < n; i++ {
		s.Record(detect.Event{
			Time: time.Unix(int64(1700000000+i), 0).Format(time.RFC3339),
			Host: "h" + pad, Destination: "1.1.1.1:443", Outbound: "direct", Upload: 1, Download: 1,
		})
	}
}

func namesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// Retention has to be changeable on a running gateway. It used to be settable
// only through serve flags, which the service manager freezes into the unit
// file — so "keep less history" meant reinstalling the service.
//
// lumberjack has no setters, so the only correct implementation swaps the
// logger. One that merely records the new numbers keeps rotating at the old
// cap, and fails here.
func TestSetRetentionAppliesTheNewCapWhileRunning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	s, err := NewStoreWithOptions(path, Options{MaxSizeMB: 500, MaxBackups: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	fill(t, s, 1000) // ~1 MiB, nowhere near a 500 MiB cap
	if got := namesIn(t, dir); len(got) != 1 {
		t.Fatalf("rotated under a 500 MiB cap: %v", got)
	}

	if err := s.SetRetention(Options{MaxSizeMB: 1, MaxBackups: 2, Compress: true}); err != nil {
		t.Fatalf("SetRetention: %v", err)
	}
	if got := s.Retention(); got.MaxSizeMB != 1 || got.MaxBackups != 2 || !got.Compress {
		t.Fatalf("Retention() = %+v, want the values just set", got)
	}

	fill(t, s, 3000) // ~3 MiB against the new 1 MiB cap
	var names []string
	for i := 0; i < 100; i++ {
		names = namesIn(t, dir)
		if len(names) > 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(names) <= 1 {
		t.Fatalf("never rotated after lowering the cap to 1 MiB: %v", names)
	}
}

// Swapping the logger must not cost us the read path. rotatedFiles() finds old
// generations by filename, so files written under the previous policy stay
// browsable — an implementation that recreated the store, or moved the file,
// would make the History page lose everything older than the last change.
func TestSetRetentionKeepsRotatedGenerationsBrowsable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	s, err := NewStoreWithOptions(path, Options{MaxSizeMB: 1, MaxBackups: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	fill(t, s, 2500) // rotate at least once under the old policy
	for i := 0; i < 100 && len(namesIn(t, dir)) < 2; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if got := namesIn(t, dir); len(got) < 2 {
		t.Fatalf("setup: expected a rotated generation, got %v", got)
	}
	_, before := s.RecentPage(10, 0, "")

	if err := s.SetRetention(Options{MaxSizeMB: 2, MaxBackups: 3, Compress: true}); err != nil {
		t.Fatalf("SetRetention: %v", err)
	}
	// One more record so the live file is non-empty under the new logger.
	fill(t, s, 1)

	items, after := s.RecentPage(10, 0, "")
	if len(items) == 0 {
		t.Fatal("no records readable after SetRetention")
	}
	if after < before {
		t.Fatalf("records disappeared across SetRetention: %d -> %d", before, after)
	}
}

// Record() takes s.mu and writes under it; SetRetention closes the old logger
// under the same lock. Under -race this catches a swap that closes a logger
// somebody is still writing to.
func TestSetRetentionIsSafeAgainstConcurrentRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			s.Record(detect.Event{
				Time: time.Unix(int64(1700000000+i), 0).Format(time.RFC3339),
				Host: "h.example", Destination: "1.1.1.1:443", Upload: 1, Download: 1,
			})
		}
	}()
	for i := 0; i < 20; i++ {
		if err := s.SetRetention(Options{MaxSizeMB: 4 + i%3, MaxBackups: 2}); err != nil {
			t.Fatalf("SetRetention: %v", err)
		}
	}
	close(stop)
	<-done
}

// Zero fields mean "use the default", both at construction and at change time —
// otherwise a caller who only wants to set MaxAgeDays would silently hand
// lumberjack a 0 size cap, which it reads as its own 100 MB default rather than
// ours.
func TestSetRetentionResolvesZeroToDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.SetRetention(Options{MaxAgeDays: 30}); err != nil {
		t.Fatal(err)
	}
	got := s.Retention()
	if got.MaxSizeMB != defaultMaxSizeMB || got.MaxBackups != defaultMaxBackups {
		t.Fatalf("Retention() = %+v, want defaults filled in for the unset fields", got)
	}
	if got.MaxAgeDays != 30 {
		t.Fatalf("MaxAgeDays = %d, want 30", got.MaxAgeDays)
	}
}
