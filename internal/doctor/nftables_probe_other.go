//go:build !linux

package doctor

// probeNftablesNetlink is Linux-only; nftables does not exist elsewhere.
// DetectNftables returns early on non-Linux, so this is never reached — it
// exists so the package still builds for the macOS desktop shell and CLI.
func probeNftablesNetlink() (bool, string) {
	return false, "nftables is Linux-only"
}
