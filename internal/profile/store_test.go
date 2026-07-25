package profile

import (
	"path/filepath"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestAddRejectsDuplicateName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	first, err := s.Add(apitypes.Profile{Name: "work", Final: "proxy"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Add(apitypes.Profile{Name: "work", Final: "direct"}); err == nil {
		t.Fatal("expected duplicate name to be rejected")
	}

	// The original profile must be untouched by the rejected duplicate.
	got, ok := s.Get(first.ID)
	if !ok || got.Final != "proxy" {
		t.Fatalf("original profile was overwritten: %+v ok=%v", got, ok)
	}
	if len(s.List()) != 1 {
		t.Fatalf("expected exactly one profile, got %d", len(s.List()))
	}
}

func TestAddThenDeleteAllowsSameNameAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	p, err := s.Add(apitypes.Profile{Name: "work"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(apitypes.Profile{Name: "work"}); err != nil {
		t.Fatalf("recreating a deleted profile's name should succeed: %v", err)
	}
}
