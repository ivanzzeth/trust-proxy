//go:build !windows

package cmd

import "syscall"

// tightenUmask makes every file this process creates owner-only.
//
// Explicit 0600 on our own writers is not enough, because not every file in the
// data directory is written by us: sing-box creates cache.db (clash mode, urltest
// results, rule-set cache) and the Tailscale state directory, and the daemon's log
// is opened by the parent before it re-execs. Those appeared as 0644 next to the
// stores we had just tightened.
//
// A umask covers the ones we do not write and the ones nobody has written yet,
// which is the more useful property: the next thing that starts keeping state in
// there will be owner-only without anyone remembering to make it so.
func tightenUmask() { syscall.Umask(0o077) }
