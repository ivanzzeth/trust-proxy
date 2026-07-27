package gateway

import (
	"encoding/json"
	"testing"
)

// --clash-addr has to reach the config, not just the API's client.
//
// It configured only the client: the port sing-box actually bound came from
// whatever the config file said. So the flag did half a job silently. Running a
// second instance with --clash-addr pointed at a free port still tried to bind
// the config's port, collided with the running gateway, and exited 1 with the
// reason only in a log file — which is how two debugging sessions on this repo
// were spent in one day, mine and the user's.
//
// The secret was already injected from its flag. Injecting one half of a
// listener's configuration and reading the other half from disk is the kind of
// asymmetry that looks fine until the two disagree.
func TestClashAPIAddressComesFromTheFlag(t *testing.T) {
	const base = `{"experimental":{"clash_api":{"external_controller":"127.0.0.1:21586","secret":"old"}}}`

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &cfg); err != nil {
		t.Fatal(err)
	}
	if err := injectClashSecret(cfg, "s3cret", "127.0.0.1:31586"); err != nil {
		t.Fatal(err)
	}

	ca := clashAPI(t, cfg)
	if got := ca["external_controller"]; got != "127.0.0.1:31586" {
		t.Fatalf("external_controller = %v, want the address the flag asked for", got)
	}
	if got := ca["secret"]; got != "s3cret" {
		t.Fatalf("secret = %v, want the injected one", got)
	}
}

// An empty flag means "leave it alone", so a config with a deliberate address
// keeps it. Overwriting with a default would be a different bug in the same
// family as the one above.
func TestClashAPIKeepsTheConfigWhenTheFlagIsEmpty(t *testing.T) {
	const base = `{"experimental":{"clash_api":{"external_controller":"192.168.1.9:9090","secret":"mine"}}}`

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &cfg); err != nil {
		t.Fatal(err)
	}
	if err := injectClashSecret(cfg, "", ""); err != nil {
		t.Fatal(err)
	}

	ca := clashAPI(t, cfg)
	if got := ca["external_controller"]; got != "192.168.1.9:9090" {
		t.Fatalf("external_controller = %v, want it untouched", got)
	}
	if got := ca["secret"]; got != "mine" {
		t.Fatalf("secret = %v, want it untouched", got)
	}
}

func clashAPI(t *testing.T, cfg map[string]json.RawMessage) map[string]any {
	t.Helper()
	var exp map[string]json.RawMessage
	if err := json.Unmarshal(cfg["experimental"], &exp); err != nil {
		t.Fatal(err)
	}
	var ca map[string]any
	if err := json.Unmarshal(exp["clash_api"], &ca); err != nil {
		t.Fatal(err)
	}
	return ca
}
