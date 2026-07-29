package doctor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDetectNftables_UsableWithoutProcfs(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	// When the live `nft list ruleset` probe works, Supported/Usable must be
	// true even if /proc/net/netfilter/nf_tables is missing — that path is
	// absent in some containers while nft still functions.
	prevStat, prevLook, prevExec := statPath, lookPath, execCmdFn
	t.Cleanup(func() { statPath, lookPath, execCmdFn = prevStat, prevLook, prevExec })

	statPath = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	lookPath = func(file string) (string, error) {
		if file == "nft" {
			return "/usr/sbin/nft", nil
		}
		return "", exec.ErrNotFound
	}
	execCmdFn = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	rep := DetectNftables(context.Background(), false)
	if !rep.HasNftBinary || !rep.Usable || !rep.Supported {
		t.Fatalf("got %+v, want binary+usable+supported without procfs", rep)
	}
}

func TestDetectNftables_ProcfsOnlyStillSupported(t *testing.T) {
	prevStat, prevLook, prevExec := statPath, lookPath, execCmdFn
	t.Cleanup(func() { statPath, lookPath, execCmdFn = prevStat, prevLook, prevExec })

	dir := t.TempDir()
	fake := filepath.Join(dir, "nf_tables")
	if err := os.WriteFile(fake, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	statPath = func(path string) (os.FileInfo, error) {
		if path == "/proc/net/netfilter/nf_tables" {
			return os.Stat(fake)
		}
		return nil, os.ErrNotExist
	}
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	execCmdFn = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "false")
	}

	rep := DetectNftables(context.Background(), false)
	if !rep.Supported {
		t.Fatalf("procfs alone should still mark supported: %+v", rep)
	}
	if rep.Usable {
		t.Fatalf("usable must stay false without nft binary: %+v", rep)
	}
}

func TestDetectNftables_UnusableWhenNftFails(t *testing.T) {
	prevStat, prevLook, prevExec := statPath, lookPath, execCmdFn
	t.Cleanup(func() { statPath, lookPath, execCmdFn = prevStat, prevLook, prevExec })

	statPath = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	lookPath = func(file string) (string, error) {
		if file == "nft" {
			return "/usr/sbin/nft", nil
		}
		return "", exec.ErrNotFound
	}
	execCmdFn = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "echo boom >&2; exit 1")
	}

	rep := DetectNftables(context.Background(), false)
	if rep.Usable || rep.Supported {
		t.Fatalf("failed nft probe must not report usable/supported: %+v", rep)
	}
	if len(rep.Errors) == 0 {
		t.Fatal("expected probe error detail")
	}
}

func TestInstallNftables_RequiresYes(t *testing.T) {
	_, err := InstallNftables(context.Background(), InstallNftablesRequest{Yes: false})
	if err == nil {
		t.Fatal("expected confirmation error")
	}
}

func TestInstallNftables_AlreadyUsableIsNoop(t *testing.T) {
	prevStat, prevLook, prevExec := statPath, lookPath, execCmdFn
	t.Cleanup(func() { statPath, lookPath, execCmdFn = prevStat, prevLook, prevExec })

	statPath = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	lookPath = func(file string) (string, error) {
		switch file {
		case "nft", "apt-get":
			return "/bin/" + file, nil
		default:
			return "", exec.ErrNotFound
		}
	}
	var cmds []string
	execCmdFn = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		cmds = append(cmds, name)
		return exec.CommandContext(ctx, "true")
	}

	rep, err := InstallNftables(context.Background(), InstallNftablesRequest{Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Usable {
		t.Fatalf("expected usable report: %+v", rep)
	}
	for _, c := range cmds {
		if c == "sh" || c == "apt-get" || c == "dnf" || c == "yum" || c == "apk" || c == "pacman" {
			t.Fatalf("package manager invoked despite already usable: %v", cmds)
		}
	}
}
