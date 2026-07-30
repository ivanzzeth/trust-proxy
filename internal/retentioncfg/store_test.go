package retentioncfg

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func TestSetPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retention.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	want := apitypes.Retention{
		// Compress is explicitly off here, not merely absent: the tri-state is the
		// whole reason the field is a pointer, so the round trip has to carry a
		// deliberate false rather than let it read as "unset".
		Log:     apitypes.RetentionRule{MaxSizeMB: 8, MaxBackups: 10, MaxAgeDays: 7, Compress: &off},
		History: apitypes.RetentionRule{MaxSizeMB: 64, MaxBackups: 4},
	}
	if _, err := s.Set(want); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := again.Get()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reloaded %+v, want %+v", got, want)
	}
	if got.Log.Compress == nil || *got.Log.Compress {
		t.Fatalf("an explicit compress:false must survive the round trip, got %v", got.Log.Compress)
	}
	if got.History.Compress != nil {
		t.Fatalf("an untouched compress must stay unset, got %v", *got.History.Compress)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		in   apitypes.Retention
		bad  bool
	}{
		{"zero means defaults", apitypes.Retention{}, false},
		{"log rotation may be disabled", apitypes.Retention{Log: apitypes.RetentionRule{MaxSizeMB: NoRotation}}, false},
		{"negative size below the sentinel", apitypes.Retention{Log: apitypes.RetentionRule{MaxSizeMB: -2}}, true},
		{"negative backups", apitypes.Retention{Log: apitypes.RetentionRule{MaxBackups: -1}}, true},
		{"negative age", apitypes.Retention{History: apitypes.RetentionRule{MaxAgeDays: -1}}, true},
		// Startup replays the live history file to rebuild aggregates, so an
		// unbounded one makes boot time grow without limit. The log has no such
		// replay, which is why only history refuses this.
		{"history rotation may NOT be disabled", apitypes.Retention{History: apitypes.RetentionRule{MaxSizeMB: NoRotation}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.in)
			if tc.bad != (err != nil) {
				t.Fatalf("Validate(%+v) = %v, bad=%v", tc.in, err, tc.bad)
			}
		})
	}
}

func TestRejectedSetLeavesTheStoreAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retention.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	good := apitypes.Retention{Log: apitypes.RetentionRule{MaxSizeMB: 8}}
	if _, err := s.Set(good); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set(apitypes.Retention{History: apitypes.RetentionRule{MaxSizeMB: NoRotation}}); err == nil {
		t.Fatal("Set accepted unbounded history")
	}
	if got := s.Get(); got != good {
		t.Fatalf("rejected Set changed the value to %+v", got)
	}
}

func TestDamagedFileSelfHealsInsteadOfBlockingStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retention.json")
	if err := os.WriteFile(path, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("a damaged retention file must not stop the gateway from booting: %v", err)
	}
	if got := s.Get(); got != (apitypes.Retention{}) {
		t.Fatalf("want zero after self-heal, got %+v", got)
	}
}
