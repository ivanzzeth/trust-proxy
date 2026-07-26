package history

import (
	"encoding/json"
	"os"
	"time"
)

// Aggregate persistence.
//
// Stats (totals, top talkers, the 24h curve) are folded in memory and were
// rebuilt at startup by replaying the live JSONL. Two consequences: the replay
// cost grew with the file, and everything in a rotated generation was silently
// dropped from the totals — after a rotation the Overview counters restarted
// from whatever the new file happened to contain.
//
// The snapshot fixes both. It records the aggregate plus how far into the live
// file it had consumed; startup restores it and folds only what came after. A
// file that shrank means rotation happened, so the new generation is folded from
// its start on top of the restored totals.

type aggSnapshot struct {
	TotalUp   int64                 `json:"total_up"`
	TotalDown int64                 `json:"total_down"`
	Conns     int64                 `json:"conns"`
	Alerts    int64                 `json:"alerts"`
	Talkers   map[string]*Talker    `json:"talkers"`
	Hours     map[int64]*HourBucket `json:"hours"`
	// Offset is the live-file size already folded into the numbers above.
	Offset int64 `json:"offset"`
}

func (s *Store) aggPath() string { return s.path + ".agg" }

// saveAggregate writes the snapshot. Caller holds mu.
//
// The offset is the live file's size right now, not a running byte counter:
// every record in that file has been folded, and after a rotation (which
// lumberjack performs invisibly) the file restarts at zero while a counter would
// keep climbing — folding the new generation a second time on the next restart.
func (s *Store) saveAggregate() {
	var offset int64
	if fi, err := os.Stat(s.path); err == nil {
		offset = fi.Size()
	}
	snap := aggSnapshot{
		TotalUp: s.totalUp, TotalDown: s.totalDown, Conns: s.conns, Alerts: s.alerts,
		Talkers: s.talkers, Hours: s.hours, Offset: offset,
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return
	}
	tmp := s.aggPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, s.aggPath())
}

// loadAggregate restores a snapshot and reports the live-file offset already
// accounted for. A missing or unreadable snapshot just means "start from zero".
func (s *Store) loadAggregate() int64 {
	b, err := os.ReadFile(s.aggPath())
	if err != nil {
		return 0
	}
	var snap aggSnapshot
	if json.Unmarshal(b, &snap) != nil {
		return 0
	}
	s.totalUp, s.totalDown, s.conns, s.alerts = snap.TotalUp, snap.TotalDown, snap.Conns, snap.Alerts
	if snap.Talkers != nil {
		s.talkers = snap.Talkers
	}
	if snap.Hours != nil {
		s.hours = snap.Hours
	}
	return snap.Offset
}

// startAggregateSaver persists the snapshot periodically so a crash costs at most
// one interval of aggregation (the records themselves are already on disk).
func (s *Store) startAggregateSaver(every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				s.mu.Lock()
				s.saveAggregate()
				s.mu.Unlock()
			}
		}
	}()
}
