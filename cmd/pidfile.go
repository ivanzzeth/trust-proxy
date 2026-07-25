package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readPidFile reads and parses a pid file written by daemonize/serve --pid.
func readPidFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("bad pid file %s: %w", path, err)
	}
	return pid, nil
}
