package whitelist_test

import (
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/liststore"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
)

func TestNotesSurviveRoundTripAndReAdd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wl.json")
	s, err := whitelist.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddIP("185.125.190.58", "Canonical NTP (Ubuntu)"); err != nil {
		t.Fatal(err)
	}
	got := s.Get()
	if note := liststore.NoteOf(got.Notes, "ip", "185.125.190.58"); note != "Canonical NTP (Ubuntu)" {
		t.Fatalf("note after add: %q", note)
	}
	// Re-add without a note keeps the existing remark.
	if _, err := s.AddIP("185.125.190.58"); err != nil {
		t.Fatal(err)
	}
	if note := liststore.NoteOf(s.Get().Notes, "ip", "185.125.190.58"); note != "Canonical NTP (Ubuntu)" {
		t.Fatalf("re-add wiped note: %q", note)
	}
	// Explicit empty clears.
	if _, err := s.AddIP("185.125.190.58", ""); err != nil {
		t.Fatal(err)
	}
	if note := liststore.NoteOf(s.Get().Notes, "ip", "185.125.190.58"); note != "" {
		t.Fatalf("expected clear, got %q", note)
	}
	// Remove drops the note key.
	if _, err := s.AddIP("185.125.190.57", "another"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveIP("185.125.190.57"); err != nil {
		t.Fatal(err)
	}
	if s.Get().Notes != nil {
		t.Fatalf("expected notes nil after remove, got %v", s.Get().Notes)
	}

	// Persistence.
	s2, err := whitelist.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.AddDomain("ntp.ubuntu.com", "Ubuntu NTP pool"); err != nil {
		t.Fatal(err)
	}
	s3, err := whitelist.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if note := liststore.NoteOf(s3.Get().Notes, "domain", "ntp.ubuntu.com"); note != "Ubuntu NTP pool" {
		t.Fatalf("persisted note: %q", note)
	}
}
