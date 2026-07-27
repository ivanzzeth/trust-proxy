package users

import (
	"path/filepath"
	"testing"
)

// A username is validated after trimming and must be stored the same way.
//
// validUsername trimmed before checking and Create stored the raw string, so
// "bob " passed validation and landed as "bob " — next to an existing "bob",
// because findLocked compares what is stored. Two accounts whose names look
// identical everywhere they are displayed, while scope.go attributes traffic by
// EqualFold on the raw value and a permit request keys its pack off it. An
// ambiguity in exactly the identifier the audit trail hangs on.
func TestCreateStoresTheTrimmedUsername(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Create("  bob  ", "bob-password-long", RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "bob" {
		t.Fatalf("stored username is %q, want %q", u.Username, "bob")
	}
	// And the padded form is now a duplicate rather than a second account.
	if _, err := s.Create("bob", "another-password-long", RoleClient); err == nil {
		t.Fatal(`"bob" was created alongside "  bob  ": two accounts with the same visible name`)
	}
}

// Logging in with the padded form works, because the person who typed it cannot
// see the difference either.
func TestAuthenticateTrimsTheUsername(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("bob", "bob-password-long", RoleClient); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(" bob ", "bob-password-long"); err != nil {
		t.Fatalf("a padded username could not log in: %v", err)
	}
}
