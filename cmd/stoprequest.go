package cmd

import "sync"

// stopRequested is closed when something other than a signal asks the gateway to
// stop — today that means the Windows Service Control Manager, which has no
// signals to send.
//
// A closed channel rather than a bool: the wait in runServe selects on it, and
// close() is the only shutdown notification that cannot be missed by a receiver
// that was not listening yet.
var (
	stopRequested = make(chan struct{})
	stopOnce      sync.Once
)

// requestStop asks a running serve to shut down. Safe to call more than once,
// which matters because the SCM can send Stop and Shutdown back to back.
func requestStop() { stopOnce.Do(func() { close(stopRequested) }) }
