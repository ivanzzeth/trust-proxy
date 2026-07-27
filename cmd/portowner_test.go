package cmd

import "testing"

func TestPortOf(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:21585": "21585",
		":21585":          "21585",
		"[::1]:21585":     "21585",
		"127.0.0.1":       "",
		"":                "",
		"host:notaport":   "",
	} {
		if got := portOf(in); got != want {
			t.Errorf("portOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirstPIDReadsLsofOutput(t *testing.T) {
	if got := firstPID("4242\n"); got != 4242 {
		t.Fatalf("got %d", got)
	}
	// Several listeners (v4 and v6 sockets of the same process is the normal case)
	// — the first is as good as any, they are the same program.
	if got := firstPID("\n4242\n4242\n"); got != 4242 {
		t.Fatalf("got %d", got)
	}
	if got := firstPID(""); got != 0 {
		t.Fatalf("empty output must yield 0, got %d", got)
	}
	if got := firstPID("lsof: command not found"); got != 0 {
		t.Fatalf("garbage must yield 0, got %d", got)
	}
}

func TestPidFromSS(t *testing.T) {
	line := `LISTEN 0 4096 127.0.0.1:21585 0.0.0.0:* users:(("trust-proxy",pid=4242,fd=9))`
	if got := pidFromSS(line); got != 4242 {
		t.Fatalf("got %d", got)
	}
	// ss without -p prints no users:(...) at all; that is "unknown", not a pid.
	if got := pidFromSS(`LISTEN 0 4096 127.0.0.1:21585 0.0.0.0:*`); got != 0 {
		t.Fatalf("a line with no pid must yield 0, got %d", got)
	}
	if got := pidFromSS(""); got != 0 {
		t.Fatalf("got %d", got)
	}
}

// The pid is the last column of a LISTENING row, and the row also carries a
// remote address — so the port has to be matched at the end of the *local*
// address, not searched for anywhere in the line.
func TestPidFromNetstatMatchesTheListeningLocalAddress(t *testing.T) {
	out := "" +
		"  Proto  Local Address          Foreign Address        State           PID\n" +
		"  TCP    127.0.0.1:21584        0.0.0.0:0              LISTENING       111\n" +
		"  TCP    127.0.0.1:21585        0.0.0.0:0              LISTENING       4242\n" +
		"  TCP    192.168.1.5:52001      93.184.216.34:21585    ESTABLISHED     999\n"
	if got := pidFromNetstat(out, "21585"); got != 4242 {
		t.Fatalf("got %d, want the listener's pid", got)
	}
	if got := pidFromNetstat(out, "21584"); got != 111 {
		t.Fatalf("got %d", got)
	}
	if got := pidFromNetstat(out, "9999"); got != 0 {
		t.Fatalf("a port nobody listens on must yield 0, got %d", got)
	}
	// An established connection *to* a port is not a listener on it.
	establishedOnly := "  TCP    192.168.1.5:52001      93.184.216.34:31000    ESTABLISHED     999\n"
	if got := pidFromNetstat(establishedOnly, "31000"); got != 0 {
		t.Fatalf("an outbound connection was mistaken for a listener: %d", got)
	}
}
