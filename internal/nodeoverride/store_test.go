package nodeoverride

import (
	"path/filepath"
	"testing"
)

func TestStore_DisableEnablePersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodeoverrides.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Disabled(); len(got) != 0 {
		t.Fatalf("fresh store disabled=%v", got)
	}
	if _, err := s.SetTag("新加坡 C", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetTag("美国 03", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetTag("新加坡 C", true); err != nil { // idempotent
		t.Fatal(err)
	}
	got := s.Disabled()
	if len(got) != 2 || got[0] != "新加坡 C" && got[0] != "美国 03" {
		t.Fatalf("disabled=%v", got)
	}
	if !s.DisabledSet()["新加坡 C"] {
		t.Fatal("set lookup miss")
	}

	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Disabled()) != 2 {
		t.Fatalf("reload lost disables: %v", s2.Disabled())
	}

	if _, err := s2.SetTag("新加坡 C", false); err != nil {
		t.Fatal(err)
	}
	if s2.DisabledSet()["新加坡 C"] {
		t.Fatal("enable left tag disabled")
	}
}

func TestStore_SetDisabledAndPrune(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetDisabled([]string{"a", "b", "a", "  "}); err != nil {
		t.Fatal(err)
	}
	if got := s.Disabled(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("normalized=%v", got)
	}
	if _, err := s.Prune([]string{"b", "c"}); err != nil {
		t.Fatal(err)
	}
	if got := s.Disabled(); len(got) != 1 || got[0] != "b" {
		t.Fatalf("after prune=%v", got)
	}
}

func TestStore_Restore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	prev, _ := s.SetDisabled([]string{"old"})
	if _, err := s.SetDisabled([]string{"new"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Restore(prev); err != nil {
		t.Fatal(err)
	}
	if got := s.Disabled(); len(got) != 1 || got[0] != "old" {
		t.Fatalf("restore=%v", got)
	}
}
