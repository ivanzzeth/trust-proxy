package cmd

import (
	"strings"
	"testing"
)

// A management port is a hole in the security floor, and it has to stay a small,
// deliberate one.
//
// The rule it produces sits at the very top — above the blacklist, above
// quarantine, above the process and device gates, above the Permit gate — matching
// on source_port so an inbound SSH session's replies always get out and a TUN
// capture cannot lock you out of the machine. Deliberate, and documented.
//
// What was not checked is the value. A port inside the ephemeral range is handed
// out to *outgoing* connections by the kernel, so listing one exempts arbitrary
// outbound traffic from every layer of the policy, at whatever rate the OS happens
// to reuse it. Nothing rejected that, and the number does not look wrong: 50000 is
// as plausible-looking as 22.
func TestManagementPortsRejectsTheEphemeralRange(t *testing.T) {
	for _, port := range []string{"32768", "40000", "60999", "49152", "65000"} {
		if _, err := managementPortsChecked(port, "127.0.0.1:21585"); err == nil {
			t.Errorf("port %s was accepted: it is in the ephemeral range, so it exempts "+
				"arbitrary outbound connections from the whole security floor", port)
		}
	}
}

// And the ports people actually use are still accepted, or the flag is useless.
func TestManagementPortsAcceptsTheUsualSuspects(t *testing.T) {
	got, err := managementPortsChecked("22,2222,8022", "127.0.0.1:21585")
	if err != nil {
		t.Fatalf("a normal management port list was refused: %v", err)
	}
	want := map[int]bool{22: true, 2222: true, 8022: true, 21585: true}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected port %d", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("missing ports: %v", want)
	}
}

// The API port is added automatically and must be exempt from the check: it is
// chosen by the operator, it is a listener rather than an ephemeral allocation, and
// refusing it would make the gateway unable to start rather than warn.
func TestTheAPIPortIsAlwaysAllowed(t *testing.T) {
	got, err := managementPortsChecked("22", "127.0.0.1:51234")
	if err != nil {
		t.Fatalf("an API port in the ephemeral range must not fail the gateway: %v", err)
	}
	var found bool
	for _, p := range got {
		if p == 51234 {
			found = true
		}
	}
	if !found {
		t.Fatal("the API port was not added")
	}
}

// The error has to say what to do. "invalid port" would send somebody looking for a
// typo in a number that is perfectly well-formed.
func TestTheRefusalExplainsItself(t *testing.T) {
	_, err := managementPortsChecked("40000", "127.0.0.1:21585")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, want := range []string{"40000", "ephemeral"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}
