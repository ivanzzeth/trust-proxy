package liststore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAddRemove(t *testing.T) {
	l := Add(nil, "b")
	l = Add(l, "a")
	l = Add(l, "b") // dup, no-op
	if got := []string{"a", "b"}; len(l) != 2 || l[0] != got[0] || l[1] != got[1] {
		t.Fatalf("Add: got %v, want sorted %v", l, got)
	}
	l = Remove(l, "a")
	if len(l) != 1 || l[0] != "b" {
		t.Fatalf("Remove: got %v", l)
	}
}

func TestFilter(t *testing.T) {
	removed := 0
	out := Filter([]string{"1.2.3.4", "not-an-ip", "10.0.0.0/8"}, ValidCIDR, &removed)
	if removed != 1 || len(out) != 2 {
		t.Fatalf("Filter: got out=%v removed=%d", out, removed)
	}
}

func TestValidCIDR(t *testing.T) {
	for _, ok := range []struct {
		s    string
		want bool
	}{
		{"10.0.0.0/8", true},
		{"1.2.3.4", true},
		{"not-a-cidr", false},
		{"", false},
	} {
		if got := ValidCIDR(ok.s); got != ok.want {
			t.Errorf("ValidCIDR(%q) = %v, want %v", ok.s, got, ok.want)
		}
	}
}

func TestMutatePersistsAndSnapshots(t *testing.T) {
	type rules struct{ Items []string }
	path := filepath.Join(t.TempDir(), "rules.json")
	var mu sync.Mutex
	data := rules{}
	snapshot := func(r rules) rules { return rules{Items: append([]string(nil), r.Items...)} }

	snap, err := Mutate(&mu, path, &data, func() { data.Items = Add(data.Items, "x") }, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Items) != 1 || snap.Items[0] != "x" {
		t.Fatalf("snapshot: got %v", snap)
	}
	// Mutating the returned snapshot must not affect the store's internal data.
	snap.Items[0] = "mutated"
	if data.Items[0] != "x" {
		t.Fatalf("snapshot aliased internal data: %v", data.Items)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var reread rules
	if err := json.Unmarshal(b, &reread); err != nil {
		t.Fatal(err)
	}
	if len(reread.Items) != 1 || reread.Items[0] != "x" {
		t.Fatalf("persisted file: got %v", reread)
	}
}
