package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// NftablesReport summarizes whether nftables is present and usable for
// auto_redirect (TUN capture) needs.
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
	statPath  = os.Stat
	lookPath  = exec.LookPath
	execCmdFn = exec.CommandContext
)

func detectNftablesInterfaceSupported() bool {
	// Presence of the procfs interface is a strong signal of kernel nftables
	// support, but some containers (and some kernel builds) hide it while
	// `nft list ruleset` still works. Prefer the live probe when available.
	_, err := statPath("/proc/net/netfilter/nf_tables")
	return err == nil
}

func detectNftUsable(ctx context.Context) (bool, string) {
	// "nft list ruleset" is the ground-truth probe: if it succeeds, sing-box
	// can install auto_redirect rules. Prefer this over the procfs path —
	// Docker already demonstrated nft works here even when
	// /proc/net/netfilter/nf_tables is absent.
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := execCmdFn(cctx, "nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		return false, strings.TrimSpace(string(out))
	}
	return true, ""
}

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

// DetectNftables builds a report for the UI/doctor.
func DetectNftables(ctx context.Context, canAutoInstall bool) NftablesReport {
	rep := NftablesReport{
		Supported:            false,
		HasNftBinary:         false,
		Usable:               false,
		AutoInstallSupported: false,
	}
	if runtime.GOOS != "linux" {
		return rep
	}

	if _, err := lookPath("nft"); err == nil {
		rep.HasNftBinary = true
	} else {
		rep.Errors = append(rep.Errors, "nft binary not found in PATH")
	}

	procOK := detectNftablesInterfaceSupported()
	if rep.HasNftBinary {
		ok, diag := detectNftUsable(ctx)
		rep.Usable = ok
		if !ok && diag != "" {
			rep.Errors = append(rep.Errors, diag)
		}
	}
	// Supported = kernel can speak nftables. Prefer the live probe; fall back
	// to procfs for environments where listing needs root and we only have the
	// interface path as evidence.
	rep.Supported = rep.Usable || procOK

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
