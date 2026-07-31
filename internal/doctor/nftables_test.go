package doctor

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// The bug this pins down was found by CI, not by reading code: in the e2e
// container, TestLinuxTUNCapturesForwardedBridgeTraffic proved auto_redirect
// built its nftables table and captured forwarded traffic, while in that same
// image `trust-proxy doctor nftables --json` reported
// {"supported": false, "has_nft_binary": true, "usable": false}.
//
// That is not a cosmetic disagreement. The DaemonSet and Helm preflight
// containers refuse to start a Pod unless `usable` is true, so the node where
// capture demonstrably works would have been rejected — the exact inverse of
// the failure the preflight exists to prevent.
//
// Root cause: Usable was computed only when the `nft` CLI was in PATH *and*
// /proc/net/netfilter/nf_tables could be stat'd. sing-tun uses neither. It
// opens an nftables netlink socket and lists tables (redirect_linux.go
// initializeNFTables), which is what these tests hold the report to.

func withProbe(t *testing.T, ok bool, diag string) {
	t.Helper()
	prev := nftablesUsable
	nftablesUsable = func() (bool, string) { return ok, diag }
	t.Cleanup(func() { nftablesUsable = prev })
}

func withLookPath(t *testing.T, found map[string]bool) {
	t.Helper()
	prev := lookPath
	lookPath = func(file string) (string, error) {
		if found[file] {
			return "/usr/sbin/" + file, nil
		}
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() { lookPath = prev })
}

// The whole point: no userspace package, capture still works, report says so.
// Revert Usable to require HasNftBinary and this fails.
func TestUsableDoesNotRequireTheNftBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("DetectNftables returns an empty report off Linux")
	}
	withProbe(t, true, "")
	withLookPath(t, nil) // nothing in PATH at all

	rep := DetectNftables(context.Background(), false)
	if !rep.Usable {
		t.Fatalf("netlink probe succeeded but report says unusable: %+v", rep)
	}
	if !rep.Supported {
		t.Fatalf("netlink probe succeeded but report says unsupported: %+v", rep)
	}
	if rep.HasNftBinary {
		t.Fatalf("no nft in PATH yet report claims one: %+v", rep)
	}
	// The missing binary is worth mentioning, since you cannot read the ruleset
	// without it — but it must read as an inconvenience, not as a failure.
	var mentioned bool
	for _, e := range rep.Errors {
		if strings.Contains(e, "nft binary") {
			mentioned = true
		}
	}
	if !mentioned {
		t.Errorf("a missing nft binary should still be reported for debuggability: %+v", rep.Errors)
	}
}

// The other direction, and the one the preflight actually depends on: when
// sing-tun would fail to program nftables, the report must not claim usable.
// Otherwise the preflight admits a node where every Pod egresses past the
// gateway while the Pod looks healthy.
func TestUsableIsFalseWhenTheNetlinkProbeFails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("DetectNftables returns an empty report off Linux")
	}
	withProbe(t, false, "nftables netlink socket: operation not permitted")
	withLookPath(t, map[string]bool{"nft": true}) // binary present, kernel not

	rep := DetectNftables(context.Background(), false)
	if rep.Usable || rep.Supported {
		t.Fatalf("netlink probe failed but report claims usable/supported: %+v", rep)
	}
	if !rep.HasNftBinary {
		t.Fatalf("nft is in PATH but report says otherwise: %+v", rep)
	}
	if len(rep.Errors) == 0 || !strings.Contains(strings.Join(rep.Errors, "|"), "operation not permitted") {
		t.Fatalf("the probe's diagnosis must survive into the report, it is the only clue an operator gets: %+v", rep.Errors)
	}
}

// Supported and Usable answer the same question and must never disagree — the
// CI failure had them agreeing with each other and disagreeing with reality,
// but a later change that gates one on the CLI and not the other would be worse
// still: consumers read whichever field they happened to pick.
func TestSupportedAndUsableAgree(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("DetectNftables returns an empty report off Linux")
	}
	for _, probeOK := range []bool{true, false} {
		for _, haveNft := range []bool{true, false} {
			withProbe(t, probeOK, "diag")
			withLookPath(t, map[string]bool{"nft": haveNft})
			rep := DetectNftables(context.Background(), false)
			if rep.Supported != rep.Usable {
				t.Fatalf("probe=%v nft=%v: supported=%v usable=%v — the two fields disagree",
					probeOK, haveNft, rep.Supported, rep.Usable)
			}
			if rep.Usable != probeOK {
				t.Fatalf("probe=%v nft=%v: usable=%v, but only the probe should decide it",
					probeOK, haveNft, rep.Usable)
			}
		}
	}
}
