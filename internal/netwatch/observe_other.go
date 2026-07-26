//go:build !darwin

package netwatch

import "time"

// Observe on platforms without a route-socket implementation here reports the
// interface picture only. Route-hijack detection is darwin-only for now rather
// than silently wrong elsewhere: a monitor that reports "no findings" because it
// cannot see the table is worse than one that says it isn't watching.
func Observe() (Snapshot, error) {
	snap := Snapshot{Taken: time.Now()}
	locals, err := localPrefixes()
	if err != nil {
		return snap, err
	}
	snap.LocalNets = locals
	return snap, nil
}

// RouteWatchSupported reports whether route-hijack detection works here.
func RouteWatchSupported() bool { return false }
