package detect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func b2r(b []byte) io.Reader { return bytes.NewReader(b) }

const (
	detMaxBytes = 64 << 20 // rotate JSONL past this size
	detMaxIndex = 10000    // in-memory newest detections kept for Query
)

// Query filters detections for the API/UI.
type Query struct {
	Kind   Kind   // empty = all
	Q      string // host/dest/process/reason substring
	Offset int
	Limit  int
}

// Page is one slice of detections plus the filtered total.
type Page struct {
	Items  []Detection `json:"items"`
	Total  int         `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

// Stats aggregates for Overview cards.
type Stats struct {
	Alerts24h  int            `json:"alerts_24h"`
	Blocked24h int            `json:"blocked_24h"`
	Banned24h  int            `json:"banned_24h"`
	ByKind     map[string]int `json:"by_kind"`
}

// Store is a durable detections log (JSONL) with an in-memory newest-first index.
type Store struct {
	path string
	mu   sync.Mutex
	f    *os.File
	size int64
	seq  uint64
	now  func() time.Time

	index []Detection // oldest → newest; Query reverses
}

// NewStore opens (creating) detections.jsonl and rebuilds the in-memory index.
func NewStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	s := &Store{path: path, now: time.Now}
	if b, err := os.ReadFile(path); err == nil {
		sc := bufio.NewScanner(b2r(b))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			var d Detection
			if json.Unmarshal(sc.Bytes(), &d) != nil {
				continue
			}
			s.index = append(s.index, d)
			if d.ID > s.seq {
				s.seq = d.ID
			}
		}
		if len(s.index) > detMaxIndex {
			s.index = s.index[len(s.index)-detMaxIndex:]
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

// Record appends a detection and updates the index. Assigns ID if zero.
func (s *Store) Record(d Detection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.ID == 0 {
		s.seq++
		d.ID = s.seq
	} else if d.ID > s.seq {
		s.seq = d.ID
	}
	if d.Time == "" {
		d.Time = s.now().Format(time.RFC3339)
	}
	line, err := json.Marshal(d)
	if err != nil {
		return
	}
	if s.f != nil {
		if s.size >= detMaxBytes {
			s.rotate()
		}
		n, _ := s.f.Write(append(line, '\n'))
		s.size += int64(n)
	}
	s.index = append(s.index, d)
	if len(s.index) > detMaxIndex {
		s.index = s.index[len(s.index)-detMaxIndex:]
	}
}

func (s *Store) rotate() {
	s.f.Close()
	_ = os.Rename(s.path, s.path+".1")
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		s.f = f
		s.size = 0
	}
}

// Query returns newest-first detections matching kind/q with offset/limit.
func (s *Store) Query(q Query) Page {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	needle := strings.ToLower(strings.TrimSpace(q.Q))
	var matched []Detection
	for i := len(s.index) - 1; i >= 0; i-- {
		d := s.index[i]
		if q.Kind != "" && d.Kind != q.Kind {
			continue
		}
		if needle != "" && !detMatch(d, needle) {
			continue
		}
		matched = append(matched, d)
	}
	total := len(matched)
	if q.Offset >= total {
		return Page{Items: []Detection{}, Total: total, Limit: q.Limit, Offset: q.Offset}
	}
	end := q.Offset + q.Limit
	if end > total {
		end = total
	}
	return Page{Items: matched[q.Offset:end], Total: total, Limit: q.Limit, Offset: q.Offset}
}

func detMatch(d Detection, needle string) bool {
	if strings.Contains(strings.ToLower(d.Host), needle) {
		return true
	}
	if strings.Contains(strings.ToLower(d.Destination), needle) {
		return true
	}
	if strings.Contains(strings.ToLower(d.Process), needle) {
		return true
	}
	for _, r := range d.Reasons {
		if strings.Contains(strings.ToLower(r), needle) {
			return true
		}
	}
	return false
}

// Stats returns 24h aggregates from the in-memory index.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-24 * time.Hour)
	st := Stats{ByKind: map[string]int{}}
	for _, d := range s.index {
		ts, err := time.Parse(time.RFC3339, d.Time)
		if err != nil || ts.Before(cutoff) {
			continue
		}
		st.Alerts24h++
		st.ByKind[string(d.Kind)]++
		switch d.Action {
		case ActionBlocked:
			st.Blocked24h++
		case ActionBanned:
			st.Banned24h++
			st.Blocked24h++ // banned implies disposed
		}
	}
	return st
}
