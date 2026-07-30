package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/tuncfg"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

func getDefaults(t *testing.T) apitypes.Defaults {
	t.Helper()
	rr := httptest.NewRecorder()
	(&Server{}).handleDefaults(rr, httptest.NewRequest(http.MethodGet, "/api/defaults", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/defaults = %d", rr.Code)
	}
	var d apitypes.Defaults
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// The endpoint's whole job is to be the one place a default is stated, so a
// value that is *reported* but never *applied* is worse than no endpoint at all:
// the console renders "(default …)" beside a blank field and the annotation is
// simply false.
//
// Two knobs have a resolved form that differs from their stored form, and both
// were reported in the stored form at first. TUN address is the sharp one — the
// store deliberately keeps it empty so the gateway can fill 198.18.0.1/30 at
// inject time, and reporting that blank made the console's default read as
// "none", which is the one address a TUN interface cannot have.
func TestDefaultsReportsWhatTakesEffectNotWhatIsStored(t *testing.T) {
	d := getDefaults(t)

	if len(d.TUN.Address) == 0 {
		t.Error("TUN address default is blank: the console will show `none` for a value " +
			"that is actually 198.18.0.1/30 (use tuncfg.Resolved, not tuncfg.Defaults)")
	}
	if !reflect.DeepEqual(d.TUN.Address, apitypes.DefaultTUNAddresses) {
		t.Errorf("TUN address default = %v, want %v", d.TUN.Address, apitypes.DefaultTUNAddresses)
	}
	if d.Inbound.Listen == "" || d.Inbound.Port == 0 {
		t.Errorf("inbound default is only half-stated: %+v", d.Inbound)
	}
	// The rest of the TUN document must still match what the store seeds, or the
	// two have drifted in the other direction.
	seed := tuncfg.Defaults()
	if d.TUN.Stack != seed.Stack || d.TUN.StrictRoute != seed.StrictRoute || d.TUN.AutoRedirect != seed.AutoRedirect {
		t.Errorf("reported TUN defaults disagree with the seeded ones: %+v vs %+v", d.TUN, seed)
	}
}
