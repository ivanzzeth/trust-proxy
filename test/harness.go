// Package test holds the end-to-end suites that need something outside this
// process: containers (docker_e2e) or a macOS VM (tart_e2e).
//
// Both are behind build tags and both skip when their dependency is missing, so
// `go test ./...` stays green on a machine with neither. This file holds what
// they share.
package test

import (
	"os"
	"path/filepath"
	"testing"
)

// repoRoot is the module root, so a test can build the binary under test.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(wd) // test/ -> repo root
}

// envOr reads an override with a default.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
