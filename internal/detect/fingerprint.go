package detect

import (
	"fmt"
	"time"
)

// TLS client fingerprints (JA4).
//
// The Permit gate matches on the destination name, and ECH encrypts it: the
// ClientHello a gateway sees will increasingly carry a cover domain. A
// fingerprint describes the client stack instead, so it stays informative when
// the name stops being — and an embedded TLS library among a machine's browsers
// is exactly the shape of an implant.
//
// Reporting rule follows the practice the JA4 authors recommend: learn what this
// machine normally offers, then report deviations. Alerting on "unknown hash"
// from a cold start would fire on every browser update.

// fingerprintState is one JA4's history.
type fingerprintState struct {
	first     time.Time
	last      time.Time
	count     int
	processes map[string]struct{}
}

// FingerprintRow is the API-facing view of one fingerprint.
type FingerprintRow struct {
	JA4       string   `json:"ja4"`
	Count     int      `json:"count"`
	First     string   `json:"first_seen"`
	Last      string   `json:"last_seen"`
	Processes []string `json:"processes,omitempty"`
}

// RecordFingerprint folds one connection's JA4 in and returns a reason when it
// is new after the learning window. Caller holds e.mu.
func (e *Engine) recordFingerprintLocked(ja4, host, process string, now time.Time) string {
	if ja4 == "" || !e.ja4Enabled {
		return ""
	}
	if e.fingerprints == nil {
		e.fingerprints = map[string]*fingerprintState{}
		e.ja4Start = now
	}
	st := e.fingerprints[ja4]
	known := st != nil
	if !known {
		if len(e.fingerprints) >= ja4Max {
			return "" // pathological variety (GREASE bug, fuzzer): stop growing
		}
		st = &fingerprintState{first: now, processes: map[string]struct{}{}}
		e.fingerprints[ja4] = st
	}
	st.count++
	st.last = now
	if process != "" {
		if len(st.processes) < 8 {
			st.processes[process] = struct{}{}
		}
	}
	if known {
		return ""
	}
	// Still learning: record, don't report.
	learn := time.Duration(e.ja4LearnMinutes) * time.Minute
	if now.Sub(e.ja4Start) < learn {
		return ""
	}
	who := process
	if who == "" {
		who = "an unidentified process"
	}
	return fmt.Sprintf(
		"new TLS client fingerprint %s from %s to %s — a stack this machine has not used before (fingerprints survive ECH, which hides the destination name)",
		ja4, who, host)
}

// Fingerprints returns the observed fingerprints, most recently seen first.
func (e *Engine) Fingerprints(limit int) []FingerprintRow {
	if limit <= 0 {
		limit = 50
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	rows := make([]FingerprintRow, 0, len(e.fingerprints))
	for ja4, st := range e.fingerprints {
		row := FingerprintRow{
			JA4: ja4, Count: st.count,
			First: st.first.Format(time.RFC3339), Last: st.last.Format(time.RFC3339),
		}
		for p := range st.processes {
			row.Processes = append(row.Processes, p)
		}
		rows = append(rows, row)
	}
	for i := 1; i < len(rows); i++ { // newest-last-seen first
		for j := i; j > 0 && rows[j].Last > rows[j-1].Last; j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// FingerprintLearning reports whether the baseline window is still open, so the
// console can say "learning" instead of implying it has nothing to report.
func (e *Engine) FingerprintLearning() (learning bool, until string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.ja4Enabled || e.ja4Start.IsZero() {
		return e.ja4Enabled, ""
	}
	end := e.ja4Start.Add(time.Duration(e.ja4LearnMinutes) * time.Minute)
	if e.now().Before(end) {
		return true, end.Format(time.RFC3339)
	}
	return false, ""
}

const ja4Max = 4096
