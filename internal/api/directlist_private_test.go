package api

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func newDLStore(t *testing.T) *directlist.Store {
	t.Helper()
	s, err := directlist.NewStore(filepath.Join(t.TempDir(), "directlist.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// PrivateDirect answers "is this machine's exit the far side of 10.0.0.0/8?" — a
// fact about the WireGuard/Tailscale endpoint it dials, not a policy choice. So a
// posture switch or a profile activation must not move it.
//
// Every snapshot taken before the switch existed has the field unset, which reads
// as "on". Without the carry-over, activating any older slot silently puts LAN
// back on the direct path — and on a site-to-site gateway that means internal
// traffic stops going through the tunnel, with nothing in the UI changed to
// explain it. Same shape as the profile that used to reopen
// interrupt_exist_connections.
func TestPolicySnapshotDoesNotCarryPrivateDirect(t *testing.T) {
	store := newDLStore(t)
	if _, err := store.SetPrivateDirect(false); err != nil {
		t.Fatal(err)
	}
	s := &Server{dl: store}

	// A slot/profile snapshot from before the field existed.
	in := policyInputs{dl: directlist.Rules{Domains: []string{"from-the-slot.example"}}}
	if in.dl.BypassPrivate() != true {
		t.Fatal("precondition: an absent field reads as on")
	}

	s.keepMachineFields(&in)

	if in.dl.BypassPrivate() {
		t.Fatal("activating a snapshot turned the built-in LAN bypass back on")
	}
	if len(in.dl.Domains) != 1 || in.dl.Domains[0] != "from-the-slot.example" {
		t.Fatalf("the snapshot's own no-proxy entries were altered: %+v", in.dl.Domains)
	}
}

// The inverse: a machine that has the floor on keeps it on when a snapshot that
// pre-dates the field is activated.
func TestPolicySnapshotKeepsTheFloorOnByDefault(t *testing.T) {
	s := &Server{dl: newDLStore(t)}
	in := policyInputs{dl: directlist.Rules{}}
	s.keepMachineFields(&in)
	if !in.dl.BypassPrivate() {
		t.Fatal("default install lost its built-in LAN bypass on a snapshot switch")
	}
}

// The snapshot wire type must not grow the field. Checked structurally rather
// than by capturing a slot: the carry-over above only holds as long as a
// snapshot has nothing to carry, and "someone helpfully added it to the
// snapshot" is exactly how that would stop holding.
func TestSnapshotDirectListHasNoPrivateDirectField(t *testing.T) {
	typ := reflect.TypeOf(apitypes.DirectList{})
	for i := 0; i < typ.NumField(); i++ {
		if name := typ.Field(i).Name; name == "PrivateDirect" {
			t.Fatal("apitypes.DirectList gained PrivateDirect: a posture/profile snapshot would then " +
				"move this machine's exit topology, and every snapshot predating the field would " +
				"switch the built-in LAN bypass back on")
		}
	}
}

// The store itself: absent means on, and the value survives a reload.
func TestDirectlistPrivateDirectPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directlist.json")
	first, err := directlist.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Get().BypassPrivate() {
		t.Fatal("a fresh store must have the built-in bypass on")
	}
	if _, err := first.SetPrivateDirect(false); err != nil {
		t.Fatal(err)
	}
	again, err := directlist.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Get().BypassPrivate() {
		t.Fatal("the switch did not survive a reload")
	}
}
