package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// NftablesReport summarizes whether nftables is present and usable for
// auto_redirect (TUN capture) needs.
//
// Supported and Usable both answer the same question — can sing-tun program
// nftables on this machine — and both are decided by the netlink probe that
// sing-tun itself runs. HasNftBinary is a *separate* fact about debuggability
// and gates nothing: sing-tun drives nftables over netlink and never shells out
// to `nft`, so a node with no userspace package captures forwarded traffic
// perfectly well. Anything that refuses to start on HasNftBinary=false is
// refusing nodes that work.
type NftablesReport struct {
	Supported            bool     `json:"supported"`
	HasNftBinary         bool     `json:"has_nft_binary"`
	Usable               bool     `json:"usable"`
	AutoInstallSupported bool     `json:"auto_install_supported"`
	SuggestedInstallCmd  string   `json:"suggested_install_cmd,omitempty"`
	SuggestedPackages    []string `json:"suggested_packages,omitempty"`
	Errors               []string `json:"errors,omitempty"`
	// InstalledAtReportedAt is filled by the caller after attempting install.
	// Kept as a string to avoid embedding time semantics in the UI.
	InstalledAtReportedAt string `json:"installed_at_reported_at,omitempty"`
}

var (
	lookPath  = exec.LookPath
	execCmdFn = exec.CommandContext
)

// nftablesUsable reports whether sing-tun's auto_redirect can program nftables
// here, by running sing-tun's own probe. probeNftablesNetlink is swappable for
// tests.
var nftablesUsable = probeNftablesNetlink

type pkgMgr struct {
	Name              string
	InstallCmd        []string
	SuggestedPackages []string
}

func detectPkgMgr() (pkgMgr, bool) {
	// Only auto-install nftables userspace. Kernel modules are usually present.
	// If a distro uses nftables elsewhere, still install the canonical package.
	if _, err := lookPath("apt-get"); err == nil {
		return pkgMgr{
			Name:              "apt-get",
			InstallCmd:        []string{"apt-get", "update", "-y", "&&", "apt-get", "install", "-y", "--no-install-recommends", "nftables"},
			SuggestedPackages: []string{"nftables"},
		}, true
	}
	if _, err := lookPath("dnf"); err == nil {
		return pkgMgr{
			Name:              "dnf",
			InstallCmd:        []string{"dnf", "install", "-y", "nftables"},
			SuggestedPackages: []string{"nftables"},
		}, true
	}
	if _, err := lookPath("yum"); err == nil {
		return pkgMgr{
			Name:              "yum",
			InstallCmd:        []string{"yum", "install", "-y", "nftables"},
			SuggestedPackages: []string{"nftables"},
		}, true
	}
	if _, err := lookPath("apk"); err == nil {
		return pkgMgr{
			Name:              "apk",
			InstallCmd:        []string{"apk", "add", "--no-cache", "nftables"},
			SuggestedPackages: []string{"nftables"},
		}, true
	}
	if _, err := lookPath("pacman"); err == nil {
		return pkgMgr{
			Name:              "pacman",
			InstallCmd:        []string{"pacman", "-S", "--noconfirm", "nftables"},
			SuggestedPackages: []string{"nftables"},
		}, true
	}
	return pkgMgr{}, false
}

// DetectNftables builds a report for the UI/doctor. ctx is retained for the
// callers' sake (this used to run a subprocess and may again); the netlink
// probe is a couple of syscalls and does not block.
func DetectNftables(_ context.Context, canAutoInstall bool) NftablesReport {
	rep := NftablesReport{}
	if runtime.GOOS != "linux" {
		return rep
	}

	// The netlink probe decides both fields, because it is the thing that
	// decides whether auto_redirect starts. Previously Usable was computed only
	// when the nft binary was present *and* /proc/net/netfilter/nf_tables
	// existed; in the e2e container neither held while capture provably worked,
	// so the report said "will not capture" about a node that captures.
	ok, diag := nftablesUsable()
	rep.Supported = ok
	rep.Usable = ok
	if !ok && diag != "" {
		rep.Errors = append(rep.Errors, diag)
	}

	// Reported, never gated on. Installing it changes nothing about capture; it
	// changes whether you can read the ruleset when a node misbehaves.
	if _, err := lookPath("nft"); err == nil {
		rep.HasNftBinary = true
	} else {
		rep.Errors = append(rep.Errors, "nft binary not found in PATH (capture does not need it; `nft list ruleset` does)")
	}

	if canAutoInstall {
		if pm, ok := detectPkgMgr(); ok {
			rep.AutoInstallSupported = true
			// apt-get uses a shell operator; preserve as a single string hint.
			rep.SuggestedInstallCmd = strings.Join(pm.InstallCmd, " ")
			rep.SuggestedPackages = append([]string(nil), pm.SuggestedPackages...)
		}
	}
	return rep
}

// InstallNftablesRequest is the confirmed request body for auto-install.
type InstallNftablesRequest struct {
	Yes bool `json:"yes"`
}

// InstallNftables attempts a best-effort auto-install of nftables userspace
// package. It is intentionally narrow (only nftables) to keep the blast radius
// small.
func InstallNftables(ctx context.Context, req InstallNftablesRequest) (NftablesReport, error) {
	if runtime.GOOS != "linux" {
		return NftablesReport{}, errors.New("auto-install is only supported on Linux")
	}
	if !req.Yes {
		return NftablesReport{}, errors.New("confirmation required (yes=true)")
	}

	// Always re-detect after install.
	canAuto := true
	pm, ok := detectPkgMgr()
	if !ok {
		return NftablesReport{}, errors.New("no known package manager found for auto-install")
	}

	rep := DetectNftables(ctx, canAuto)
	if rep.Usable && rep.HasNftBinary {
		return rep, nil
	}

	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// apt-get needs an update+install combined line; run via shell to keep the
	// command detection logic simple and deterministic.
	if pm.Name == "apt-get" {
		cmdline := strings.Join(pm.InstallCmd, " ")
		out, err := execCmdFn(cctx, "sh", "-c", cmdline).CombinedOutput()
		if err != nil {
			rep.Errors = append(rep.Errors, strings.TrimSpace(string(out)))
			b, _ := json.Marshal(rep)
			return rep, errors.New("install nftables failed: " + string(b))
		}
	} else {
		out, err := execCmdFn(cctx, pm.InstallCmd[0], pm.InstallCmd[1:]...).CombinedOutput()
		if err != nil {
			rep.Errors = append(rep.Errors, strings.TrimSpace(string(out)))
			return rep, errors.New("install nftables failed")
		}
	}

	// Refresh.
	rep2 := DetectNftables(ctx, canAuto)
	return rep2, nil
}
