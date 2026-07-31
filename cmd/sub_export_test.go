package cmd

import (
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// The rebuild hint is meant to be pasted into a shell on the other machine, so
// the two things it must never do are emit a flag with an empty value and emit an
// unquoted URL.
//
// An empty `--ua ''` is not a no-op: it overrides the server's default
// User-Agent with the empty string, and UA gating is precisely how airports
// refuse a fetch — the subscription would arrive with zero nodes and the reason
// would be a flag the operator never chose to set.
func TestRenderSubExportEmitsNoEmptyFlags(t *testing.T) {
	got := renderSubExport(apitypes.SubscriptionExport{
		ID:   "s1",
		Name: "airport",
		URL:  "https://x.example/api/v1/client/subscribe?token=abc&flag=clash",
	})
	for _, absent := range []string{"--ua", "--via"} {
		if strings.Contains(got, absent) {
			t.Errorf("hint carries %s for a field that was empty:\n%s", absent, got)
		}
	}
	if !strings.Contains(got, "--name airport") {
		t.Errorf("hint dropped the name:\n%s", got)
	}
	// ? and & are shell metacharacters; a bare paste globs and backgrounds.
	if !strings.Contains(got, "'https://x.example/api/v1/client/subscribe?token=abc&flag=clash'") {
		t.Errorf("hint left the URL unquoted:\n%s", got)
	}
}

// The name that actually motivated this feature is 袁兴机场订阅. Non-ASCII is
// outside the "no shell treats this specially" set, so it has to come back
// quoted — otherwise the paste breaks on the machine it was written for.
func TestRenderSubExportQuotesNonASCIINames(t *testing.T) {
	got := renderSubExport(apitypes.SubscriptionExport{
		ID: "s1", Name: "袁兴机场订阅", URL: "https://x.example/sub",
	})
	if !strings.Contains(got, "--name '袁兴机场订阅'") {
		t.Errorf("hint left a non-ASCII name unquoted:\n%s", got)
	}
}

func TestRenderSubExportCarriesEverySetKnob(t *testing.T) {
	got := renderSubExport(apitypes.SubscriptionExport{
		ID: "s1", Name: "airport",
		URL:       "https://x.example/sub",
		UserAgent: "clash-verge/v2.0.0",
		Via:       "socks5://10.0.0.1:1080",
	})
	for _, want := range []string{"--name airport", "--ua clash-verge/v2.0.0", "--via socks5://10.0.0.1:1080"} {
		if !strings.Contains(got, want) {
			t.Errorf("hint lost %s:\n%s", want, got)
		}
	}
}

// A pasted subscription has no URL, so `sub add` is the wrong advice — and the
// node text can be tens of KB, which is not something to print into a terminal.
func TestRenderSubExportPointsPastedOnesAtImport(t *testing.T) {
	got := renderSubExport(apitypes.SubscriptionExport{
		ID: "s1", Name: "manual", Content: strings.Repeat("vless://x\n", 100),
	})
	if !strings.Contains(got, "sub import") {
		t.Errorf("a pasted subscription should be recreated with sub import:\n%s", got)
	}
	if strings.Contains(got, "vless://") {
		t.Errorf("the hint dumped the node text into the terminal:\n%s", got)
	}
}
