package quarantine

import "testing"

// In proxy/socks mode sing-box dials by name, so the detector's ban carries a
// hostname where an address would go. Rejecting the whole entry was the bug: the
// connection was already killed, yet nothing appeared on the list, so the
// destination could be neither seen nor released.
func TestAddKeepsDomainWhenIPArgIsNotAnAddress(t *testing.T) {
	s, err := NewStore(t.TempDir() + "/q.json")
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.Add("upload.example.com", "upload.example.com:443", "large upload")
	if err == nil {
		t.Error("want the rejected value reported, got nil error")
	}
	if len(list.Entries) != 1 {
		t.Fatalf("want the domain kept, got %+v", list.Entries)
	}
	if got := list.Entries[0]; got.Value != "upload.example.com" || got.IsIP {
		t.Fatalf("want domain entry, got %+v", got)
	}
	if len(list.Domains()) != 1 || len(list.IPs()) != 0 {
		t.Fatalf("injection view wrong: domains=%v ips=%v", list.Domains(), list.IPs())
	}
	// Persisted, so the console sees it after a restart.
	reloaded, err := NewStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Get().Entries) != 1 {
		t.Fatalf("not persisted: %+v", reloaded.Get().Entries)
	}
	// And it can be released, which is the whole point of being on the list.
	after, err := reloaded.Release("upload.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Entries) != 0 {
		t.Fatalf("release failed: %+v", after.Entries)
	}
}

// With nothing valid to keep, the caller must still hear about it.
func TestAddRejectsWhenOnlyValueIsInvalid(t *testing.T) {
	s, err := NewStore(t.TempDir() + "/q.json")
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.Add("", "not-an-ip", "x")
	if err == nil {
		t.Error("want error")
	}
	if len(list.Entries) != 0 {
		t.Fatalf("want nothing stored, got %+v", list.Entries)
	}
}
