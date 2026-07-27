package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The desktop shell's version lives in three files, and they must agree.
//
// The Go binary needs none of this — its version comes from `git describe` at
// build time and from the tag in CI. A bundler cannot read a git tag, so the
// shell's number has to sit in package.json, tauri.conf.json and Cargo.toml as
// a literal, and three literals is three chances to update two of them. They
// had already reached 0.7.0 / 0.9.0 / 0.7.0 before anyone looked.
//
// scripts/release.sh is the only thing that should write them. This is what
// makes that true: a script nobody is forced to run drifts exactly as fast as
// no script at all, and the symptom — an .app reporting a version that is not
// the release it came from — surfaces long after the commit that caused it.
func TestTheDesktopVersionAgreesWithItself(t *testing.T) {
	root := repoRoot(t)
	jsonVersion := regexp.MustCompile(`"version":\s*"([^"]+)"`)
	tomlVersion := regexp.MustCompile(`(?m)^version = "([^"]+)"`)

	found := map[string]string{}
	for _, f := range []struct {
		path string
		re   *regexp.Regexp
	}{
		{"desktop/package.json", jsonVersion},
		{"desktop/src-tauri/tauri.conf.json", jsonVersion},
		{"desktop/src-tauri/Cargo.toml", tomlVersion},
	} {
		b, err := os.ReadFile(filepath.Join(root, f.path))
		if err != nil {
			t.Skipf("not a checkout (%v)", err) // a module consumer has no desktop/
		}
		m := f.re.FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s has no version field any more — scripts/release.sh writes it, "+
				"so it has to be findable the same way", f.path)
		}
		found[f.path] = string(m[1])
	}

	var first, firstPath string
	for path, v := range found {
		if firstPath == "" {
			first, firstPath = v, path
			continue
		}
		if v != first {
			t.Fatalf("the desktop version disagrees with itself:\n  %s = %s\n  %s = %s\n\n"+
				"set them all at once:  scripts/release.sh <version>", firstPath, first, path, v)
		}
	}
}

// repoRoot walks up to the module root so the test does not depend on where it
// was invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("no go.mod above the working directory")
		}
		dir = parent
	}
}
