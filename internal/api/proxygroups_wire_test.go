package api

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/proxyscore"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// The scoring and failover policies travel inside profile and posture snapshots
// (posture.go, profiles.go, policysnapshot.go all go through these two
// converters). A field that exists in the store but not in the converter is
// silently dropped, and the symptom arrives much later: activating an old
// profile quietly restores a stock value over the tuning the user chose. That
// already happened once with failover's interrupt flag.
//
// So this does not check a hand-written list of fields — a hand-written list is
// the thing that goes stale. It fills every field with a distinct non-zero
// value by reflection and requires the round trip to preserve all of them, which
// means adding a field to either struct without wiring it fails here.
func TestScoringSurvivesTheWireRoundTrip(t *testing.T) {
	var in proxyscore.Config
	fillDistinct(t, reflect.ValueOf(&in).Elem())

	got := wireScoring(scoringWire(in))
	if !reflect.DeepEqual(in, got) {
		t.Fatalf("scoring lost fields on the wire round trip:\n in  = %+v\n out = %+v", in, got)
	}
}

func TestFailoverSurvivesTheWireRoundTrip(t *testing.T) {
	var in proxygroups.Failover
	fillDistinct(t, reflect.ValueOf(&in).Elem())

	got := wireFailover(failoverWire(in))
	if !reflect.DeepEqual(in, got) {
		t.Fatalf("failover lost fields on the wire round trip:\n in  = %+v\n out = %+v", in, got)
	}
}

// The wire struct must not carry fields the store cannot hold either: a knob the
// API accepts and then discards reads as "saved" and does nothing.
func TestWireStructsHaveNoOrphanFields(t *testing.T) {
	for _, tc := range []struct{ store, wire reflect.Type }{
		{reflect.TypeOf(proxyscore.Config{}), reflect.TypeOf(apitypes.ProxyScoring{})},
		{reflect.TypeOf(proxygroups.Failover{}), reflect.TypeOf(apitypes.ProxyFailover{})},
	} {
		if tc.store.NumField() != tc.wire.NumField() {
			t.Errorf("%s has %d fields but %s has %d — one side has an unwired knob",
				tc.store, tc.store.NumField(), tc.wire, tc.wire.NumField())
		}
	}
}

// fillDistinct writes a different non-zero value into every field, so a
// converter that copies the wrong field (rather than dropping it) also fails.
func fillDistinct(t *testing.T, v reflect.Value) {
	t.Helper()
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int, reflect.Int64:
			// Positive and unique. Not sequential: 1,2,3… would let a converter
			// that swaps two adjacent fields slip through on a lucky pairing.
			f.SetInt(int64(100 + i*7 + rnd.Intn(3)))
		default:
			t.Fatalf("%s.%s is a %s — extend fillDistinct before adding it",
				v.Type(), v.Type().Field(i).Name, f.Kind())
		}
	}
}
