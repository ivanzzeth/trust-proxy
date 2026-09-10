package service

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// No build target may start a gateway behind the service manager's back.
//
// `make redeploy` used to do exactly that: it ran
//
//	sudo sh -c '... cd $(CURDIR) && ./trust-proxy serve --daemon \
//	    --data $(HOME)/.trust-proxy --mode tun'
//
// Four rules broken by one line that an operator's fingers reach for by name.
// The process would not be owned by launchd/systemd, so `env` reports `takeover`
// and the installed service is never the thing running. Root would write into a
// login user's home, which is what poisons that directory for the desktop shell
// afterwards — and that failure surfaces three steps later as "the app will not
// open". --mode would override whatever this machine has in its store. And it
// never stopped the real service, so the new instance merely failed to bind
// 21584 while the operator was told "done".
//
// `install` is the only supported way in, and it is idempotent, so re-running it
// IS the upgrade. Checked here rather than in a comment because the wrong form
// looked perfectly reasonable for as long as it existed.
func TestNoMakeTargetStartsAGatewayOutsideTheServiceManager(t *testing.T) {
	path := filepath.Join("..", "..", "Makefile")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no Makefile next to the module (%v)", err)
	}

	// Only recipe lines matter: prose and comments are allowed to describe the
	// mistake, which is how this one is documented.
	var recipes []string
	for i, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "\t") {
			continue
		}
		body := strings.TrimLeft(line, "\t")
		if strings.HasPrefix(body, "#") || strings.HasPrefix(body, "@echo") || strings.HasPrefix(body, "echo") {
			continue
		}
		recipes = append(recipes, string(rune(i+1))+body)
	}
	joined := strings.Join(recipes, "\n")

	if m := regexp.MustCompile(`(?m)^.*sudo[^\n]*\bserve\b`).FindString(joined); m != "" {
		t.Errorf("a Makefile recipe runs `serve` under sudo, which creates a gateway no service manager owns:\n\t%s\nUse `install` — it is idempotent, so re-running it is the upgrade.", strings.TrimSpace(m))
	}
	if m := regexp.MustCompile(`(?m)^.*sudo[^\n]*--data[^\n]*(\$\(HOME\)|~/)`).FindString(joined); m != "" {
		t.Errorf("a Makefile recipe hands a home-directory path to a sudo'd command; root-owned files in a login user's home break the desktop shell later:\n\t%s", strings.TrimSpace(m))
	}
	if m := regexp.MustCompile(`\.trust-proxy\b`).FindString(joined); m != "" {
		t.Errorf("a Makefile recipe still references the per-user data directory %q, which no longer exists; the machine-wide one is the only one", m)
	}
}
