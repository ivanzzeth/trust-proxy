package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Query-level observation.
//
// Until now detection only saw domains that became connections. That misses the
// two shapes that matter most for DNS abuse, because neither produces a
// connection at all:
//
//   - a DGA sweep is mostly NXDOMAIN — malware tries hundreds of generated names
//     to find the one that resolves, and only that one is ever dialled;
//   - a DNS tunnel encodes payload into query names (and often TXT/NULL types),
//     so the "traffic" is the queries themselves.
//
// Everything here is counted in fixed-size windows keyed by client and by
// parent domain, so the cost per query is a map lookup and a couple of adds —
// this runs on the resolution path.

// QueryKinds worth counting separately; anything else is "other".
const (
	qtypeTXT  = "TXT"
	qtypeNULL = "NULL"
	qtypeANY  = "ANY"
)

// queryWindow is one client's (or parent's) recent activity.
type queryWindow struct {
	start     time.Time
	total     int
	nxdomain  int
	oddType   int
	lastAlert time.Time
}

// QueryStats is the API-facing snapshot of query-level activity.
type QueryStats struct {
	Total      int64            `json:"total"`
	NXDomain   int64            `json:"nxdomain"`
	OddType    int64            `json:"odd_type"`
	ECHAnswers int64            `json:"ech_answers"` // answers carrying an ECH config
	ECHDomains []string         `json:"ech_domains"` // names that published one
	Windows    int              `json:"tracked_windows"`
	TopParents []ParentQueryRow `json:"top_parents"`
}

// ParentQueryRow is one parent domain's query volume.
type ParentQueryRow struct {
	Parent   string `json:"parent"`
	Queries  int    `json:"queries"`
	NXDomain int    `json:"nxdomain"`
}

// RecordQuery folds one resolved query into the query-level detectors. name is
// the queried name, qtype its RR type ("A"/"TXT"/…), rcode the response code
// ("NOERROR"/"NXDOMAIN"/…) and client the asking address (may be empty).
// Returns any findings; the caller emits them (keeping this lock-free of the
// detection sink).
func (e *Engine) RecordQuery(client, name, qtype, rcode string) []Detection {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return nil
	}
	now := e.now()

	e.mu.Lock()
	cfg := e.queryCfgLocked()
	e.queryTotal++
	nx := strings.EqualFold(rcode, "NXDOMAIN")
	odd := isOddQType(qtype)
	if nx {
		e.queryNX++
	}
	if odd {
		e.queryOdd++
	}

	var reasons []string
	// (1) NXDOMAIN burst: the classic DGA sweep. Keyed by client where the
	// resolver knows one; queries the gateway itself resolves (hijacked DNS on
	// this box) carry no source, and a sweep from "the box" is just as much a
	// sweep — bucketing those together is what makes the signal work at all.
	if cfg.nxBurst > 0 {
		key := client
		if key == "" {
			key = "(local)"
		}
		w := e.bumpWindow(e.nxWindows, key, now, cfg.window)
		w.total++
		if nx {
			w.nxdomain++
		}
		if w.nxdomain >= cfg.nxBurst && e.readyToAlert(w, now, cfg.window) {
			who := client
			if who == "" {
				who = "this host"
			}
			reasons = append(reasons, fmt.Sprintf(
				"%d NXDOMAIN answers from %s in %s (%d queries) — possible DGA sweep",
				w.nxdomain, who, cfg.window, w.total))
		}
	}
	// (2) Query volume under one parent: tunnels move data as names.
	parent := parentDomain(name)
	if cfg.parentRate > 0 && parent != "" {
		w := e.bumpWindow(e.parentWindows, parent, now, cfg.window)
		w.total++
		if nx {
			w.nxdomain++ // surfaced per parent in QueryStats
		}
		if odd {
			w.oddType++
		}
		if w.total >= cfg.parentRate && e.readyToAlert(w, now, cfg.window) {
			reasons = append(reasons, fmt.Sprintf(
				"%d queries under %s in %s — possible DNS tunnel",
				w.total, parent, cfg.window))
		} else if cfg.oddTypeAt > 0 && w.oddType >= cfg.oddTypeAt && e.readyToAlert(w, now, cfg.window) {
			reasons = append(reasons, fmt.Sprintf(
				"%d %s/%s/%s queries under %s — payload-carrying record types",
				w.oddType, qtypeTXT, qtypeNULL, qtypeANY, parent))
		}
	}
	// (3) The name itself: reuse the shape scoring the connection path uses, so a
	// tunnel is caught even when its queries never resolve into a dial.
	if e.dgaEnabled {
		reasons = append(reasons, e.analyzeDomain(name, now)...)
	}
	e.mu.Unlock()

	if len(reasons) == 0 {
		return nil
	}
	ev := &Event{
		Time: now.Format(time.RFC3339), Network: "dns", Host: name,
		Destination: name, Source: client, Level: "alert", Reasons: reasons,
	}
	e.mu.Lock()
	d := e.makeDetectionLocked(KindDNS, ActionAlert, ev, reasons)
	e.mu.Unlock()
	return []Detection{d}
}

// QueryStats returns the query-level counters and the busiest parents.
func (e *Engine) QueryStats(top int) QueryStats {
	if top <= 0 {
		top = 10
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	echNames := make([]string, 0, len(e.echDomains))
	for n := range e.echDomains {
		echNames = append(echNames, n)
		if len(echNames) >= top {
			break
		}
	}
	sort.Strings(echNames)
	st := QueryStats{
		Total: e.queryTotal, NXDomain: e.queryNX, OddType: e.queryOdd,
		ECHAnswers: e.echTotal, ECHDomains: echNames,
		Windows:    len(e.parentWindows),
		TopParents: make([]ParentQueryRow, 0, top),
	}
	for parent, w := range e.parentWindows {
		st.TopParents = append(st.TopParents, ParentQueryRow{Parent: parent, Queries: w.total, NXDomain: w.nxdomain})
	}
	// Small maps; an insertion sort keeps the output stable without a dependency.
	for i := 1; i < len(st.TopParents); i++ {
		for j := i; j > 0 && st.TopParents[j].Queries > st.TopParents[j-1].Queries; j-- {
			st.TopParents[j], st.TopParents[j-1] = st.TopParents[j-1], st.TopParents[j]
		}
	}
	if len(st.TopParents) > top {
		st.TopParents = st.TopParents[:top]
	}
	return st
}

// queryTunables is the resolved config for the query detectors.
type queryTunables struct {
	window     time.Duration
	nxBurst    int
	parentRate int
	oddTypeAt  int
}

func (e *Engine) queryCfgLocked() queryTunables {
	return queryTunables{
		window:     time.Duration(e.queryWindowSec) * time.Second,
		nxBurst:    e.queryNXBurst,
		parentRate: e.queryParentRate,
		oddTypeAt:  e.queryOddTypeAt,
	}
}

// bumpWindow returns the live window for key, rolling it over when it expired.
// Caller holds e.mu.
func (e *Engine) bumpWindow(m map[string]*queryWindow, key string, now time.Time, window time.Duration) *queryWindow {
	w := m[key]
	if w == nil || now.Sub(w.start) > window {
		if len(m) > queryWindowMax {
			for k, old := range m { // opportunistic sweep of expired keys
				if now.Sub(old.start) > window {
					delete(m, k)
				}
			}
		}
		w = &queryWindow{start: now}
		if old := m[key]; old != nil {
			w.lastAlert = old.lastAlert // keep the cooldown across a rollover
		}
		m[key] = w
	}
	return w
}

// readyToAlert applies a per-window cooldown so one busy tunnel doesn't emit a
// finding per query. Caller holds e.mu.
func (e *Engine) readyToAlert(w *queryWindow, now time.Time, window time.Duration) bool {
	if !w.lastAlert.IsZero() && now.Sub(w.lastAlert) < window {
		return false
	}
	w.lastAlert = now
	return true
}

const queryWindowMax = 4096

func isOddQType(qtype string) bool {
	switch strings.ToUpper(qtype) {
	case qtypeTXT, qtypeNULL, qtypeANY:
		return true
	}
	return false
}

// parentDomain returns the registrable-ish parent (last two labels). It is
// deliberately cheap: exact eTLD+1 resolution happens in analyzeDomain, which
// already consults the public suffix list.
func parentDomain(name string) string {
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return ""
	}
	return strings.Join(labels[len(labels)-2:], ".")
}
