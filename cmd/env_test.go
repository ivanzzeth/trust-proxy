package cmd

import "testing"

// The decision table the desktop shell renders.
//
// It used to be one question — "does anything answer on the port?" — and attach
// whenever the answer was yes. That is correct in exactly one of these rows and
// silently wrong in two: an upgraded app attaches to the old daemon and shows its
// console with nothing anywhere saying the new binary was never used, and a
// gateway somebody left running by hand is adopted forever instead of being
// replaced by the managed service.
//
// Silent wrongness is why this is a table and not an if-chain in Rust.
func TestActionCoversTheFourStatesOfAMachine(t *testing.T) {
	supported := envServiceInfo{Supported: true}
	installed := envServiceInfo{Supported: true, Installed: true}
	running := envServiceInfo{Supported: true, Installed: true, Running: true}

	for _, tc := range []struct {
		name string
		env  envInfo
		want string
	}{
		{
			"nothing here yet",
			envInfo{Service: supported},
			ActionInstall,
		},
		{
			"the system gateway, current",
			envInfo{Service: running, Gateway: envGatewayInfo{Healthy: true, Managed: true}},
			ActionAttach,
		},
		{
			// The upgrade case. The app is new, the daemon is the copy `install`
			// made last time, and every page would look perfectly fine.
			"the system gateway, older than this build",
			envInfo{Service: running, Gateway: envGatewayInfo{Healthy: true, Managed: true, Stale: true}},
			ActionUpdate,
		},
		{
			// The legacy case: a `serve --daemon` from before this machine had a
			// service. Attaching to it means the service never gets installed.
			"something on the port that is not the service",
			envInfo{Service: supported, Gateway: envGatewayInfo{Healthy: true}},
			ActionTakeover,
		},
		{
			// Even when a service is registered: if the thing answering is not the
			// managed copy, it is in the way, not in charge.
			"a stray gateway while a service is also installed",
			envInfo{Service: installed, Gateway: envGatewayInfo{Healthy: true}},
			ActionTakeover,
		},
		{
			"installed but down",
			envInfo{Service: installed},
			ActionRepair,
		},
		{
			"no service implementation on this platform",
			envInfo{Service: envServiceInfo{}},
			ActionUnsupported,
		},
		{
			// Nothing to offer on a platform with no service, even with a gateway
			// up — telling someone to install what does not exist is worse than
			// saying so.
			"a gateway up on a platform with no service implementation",
			envInfo{Service: envServiceInfo{}, Gateway: envGatewayInfo{Healthy: true}},
			ActionUnsupported,
		},
	} {
		if got := decideAction(tc.env); got != tc.want {
			t.Errorf("%s: action = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Stale is decided against *this* binary, and only when the running gateway
// actually said which build it is. An older gateway does not report a version;
// reading that silence as "same build" would restore the silent no-op, so it
// falls through to takeover instead — being wrong in the direction that offers to
// fix something rather than the one that hides it.
func TestAnUnknownRemoteVersionIsNotTreatedAsCurrent(t *testing.T) {
	e := envInfo{
		Service: envServiceInfo{Supported: true, Installed: true, Running: true},
		Gateway: envGatewayInfo{Healthy: true, Version: "", Managed: false},
	}
	if got := decideAction(e); got != ActionTakeover {
		t.Fatalf("a gateway that will not say what it is should be taken over, got %q", got)
	}
}
