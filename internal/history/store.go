// Package history is a durable, per-connection traffic log. Each completed
// connection (from the detection engine's finalize sink) is appended to a JSONL
// file and folded into in-memory aggregates (totals, top talkers, hourly
// buckets) for the console's History view and detection baselines.
package history

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"
)

func b2r(b []byte) io.Reader { return bytes.NewReader(b) }
func contains(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

const (
	maxBytes    = 64 << 20 // rotate the JSONL past this size
	hourWindow  = 24       // hourly buckets kept
	maxTalkers  = 500      // prune talker map past this
	topTalkersN = 20
)

// Record is one completed connection (compact keys — the file can get long).
type Record struct {
	Time     string `json:"t"`
	Host     string `json:"h"`
	Dest     string `json:"d,omitempty"`
	Process  string `json:"p,omitempty"`
	Outbound string `json:"o,omitempty"`
	Up       int64  `json:"u"`
	Down     int64  `json:"dn"`
	Denied   bool   `json:"x,omitempty"`
	Level    string `json:"l,omitempty"`
}

type Talker struct {
	Host  string `json:"host"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
	Count int64  `json:"count"`
}
type HourBucket struct {
	Hour  int64 `json:"hour"` // unix seconds at hour start
	Up    int64 `json:"up"`
	Down  int64 `json:"down"`
	Count int64 `json:"count"`
}
type Stats struct {
	TotalUp     int64        `json:"total_up"`
	TotalDown   int64        `json:"total_down"`
	Connections int64        `json:"connections"`
	Blocked     int64        `json:"blocked"`
	Alerts      int64        `json:"alerts"`
	TopTalkers  []Talker     `json:"top_talkers"`
	Hourly      []HourBucket `json:"hourly"`
}

// Store is a file-backed connection history, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	f    *os.File
	size int64
	now  func() time.Time

	totalUp, totalDown       int64
	conns, blocked, alerts   int64
	talkers                  map[string]*Talker
	hours                    map[int64]*HourBucket
}

// NewStore opens (creating) the JSONL at path and rebuilds aggregates from it.
func NewStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	s := &Store{path: path, now: time.Now, talkers: map[string]*Talker{}, hours: map[int64]*HourBucket{}}
	if b, err := os.ReadFile(path); err == nil {
		sc := bufio.NewScanner(b2r(b))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			var r Record
			if json.Unmarshal(sc.Bytes(), &r) == nil {
				s.fold(r)
			}
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s.f = f
	if fi, err := f.Stat(); err == nil {
		s.size = fi.Size()
	}
	return s, nil
}

// Record appends a completed connection and updates aggregates.
func (s *Store) Record(e detect.Event) {
	r := Record{
		Time: e.Time, Host: e.Host, Dest: e.Destination, Process: e.Process,
		Outbound: e.Outbound, Up: e.Upload, Down: e.Download, Denied: e.Denied, Level: e.Level,
	}
	line, err := json.Marshal(r)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		if s.size >= maxBytes {
			s.rotate()
		}
		n, _ := s.f.Write(append(line, '\n'))
		s.size += int64(n)
	}
	s.fold(r)
	s.prune()
}

// rotate renames the current file aside and opens a fresh one (caller holds mu).
func (s *Store) rotate() {
	s.f.Close()
	_ = os.Rename(s.path, s.path+".1")
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		s.f = f
		s.size = 0
	}
}

// fold updates aggregates for one record (caller holds mu, or during load).
func (s *Store) fold(r Record) {
	s.totalUp += r.Up
	s.totalDown += r.Down
	s.conns++
	if r.Denied {
		s.blocked++
	}
	if r.Level == "alert" {
		s.alerts++
	}
	if r.Host != "" {
		t := s.talkers[r.Host]
		if t == nil {
			t = &Talker{Host: r.Host}
			s.talkers[r.Host] = t
		}
		t.Up += r.Up
		t.Down += r.Down
		t.Count++
	}
	if ts, err := time.Parse(time.RFC3339, r.Time); err == nil {
		hk := ts.Truncate(time.Hour).Unix()
		h := s.hours[hk]
		if h == nil {
			h = &HourBucket{Hour: hk}
			s.hours[hk] = h
		}
		h.Up += r.Up
		h.Down += r.Down
		h.Count++
	}
}

// prune bounds the talker map and drops hourly buckets outside the window.
func (s *Store) prune() {
	cutoff := s.now().Add(-hourWindow * time.Hour).Truncate(time.Hour).Unix()
	for k := range s.hours {
		if k < cutoff {
			delete(s.hours, k)
		}
	}
	if len(s.talkers) > maxTalkers {
		list := make([]*Talker, 0, len(s.talkers))
		for _, t := range s.talkers {
			list = append(list, t)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Up+list[i].Down > list[j].Up+list[j].Down })
		s.talkers = map[string]*Talker{}
		for _, t := range list[:maxTalkers/2] {
			s.talkers[t.Host] = t
		}
	}
}

// Stats returns an aggregate snapshot: totals, top talkers, last-24h hourly.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{
		TotalUp: s.totalUp, TotalDown: s.totalDown,
		Connections: s.conns, Blocked: s.blocked, Alerts: s.alerts,
	}
	talkers := make([]Talker, 0, len(s.talkers))
	for _, t := range s.talkers {
		talkers = append(talkers, *t)
	}
	sort.Slice(talkers, func(i, j int) bool { return talkers[i].Up+talkers[i].Down > talkers[j].Up+talkers[j].Down })
	if len(talkers) > topTalkersN {
		talkers = talkers[:topTalkersN]
	}
	st.TopTalkers = talkers

	cutoff := s.now().Add(-hourWindow * time.Hour).Truncate(time.Hour).Unix()
	hours := make([]HourBucket, 0, len(s.hours))
	for _, h := range s.hours {
		if h.Hour >= cutoff {
			hours = append(hours, *h)
		}
	}
	sort.Slice(hours, func(i, j int) bool { return hours[i].Hour < hours[j].Hour })
	st.Hourly = hours
	return st
}

// Recent returns up to limit newest records, optionally filtered by host
// substring. Reads the JSONL. Prefer RecentPage when the UI needs totals/offset.
func (s *Store) Recent(limit int, host string) []Record {
	page, _ := s.RecentPage(limit, 0, host)
	return page
}

// Page is one slice of history plus the filtered total for pagination.
type Page struct {
	Items  []Record `json:"items"`
	Total  int      `json:"total"`
	Limit  int      `json:"limit"`
	Offset int      `json:"offset"`
}

// RecentPage returns newest-first records matching q (host/dest/process/outbound
// substring), with offset/limit for UI pagination. total is the filtered count.
func (s *Store) RecentPage(limit, offset int, q string) ([]Record, int) {
	if limit <= 0 || limit > 2000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return []Record{}, 0
	}
	var recs []Record
	sc := bufio.NewScanner(b2r(b))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		if q != "" && !(contains(r.Host, q) || contains(r.Dest, q) || contains(r.Process, q) || contains(r.Outbound, q)) {
			continue
		}
		recs = append(recs, r)
	}
	total := len(recs)
	// newest first
	out := make([]Record, 0, limit)
	start := total - 1 - offset
	for i := start; i >= 0 && len(out) < limit; i-- {
		out = append(out, recs[i])
	}
	return out, total
}
