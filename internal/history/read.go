package history

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
)

// Reading the history without re-reading the history.
//
// RecentPage used to parse every record in every generation on each call, so the
// console's 5-second poll cost ~300ms of CPU and a full multi-MB read no matter
// how few rows it asked for — the same file the connection-close path is
// appending to. Two changes fix that:
//
//   - unfiltered pages (what the console actually polls) read only the tail of
//     the live file and take their total from a line count that is updated
//     incrementally, so the cost tracks the page size, not the corpus;
//   - filtered pages still visit every line, but skip JSON entirely for lines
//     that cannot match (a raw substring test on the bytes), so only real hits
//     are decoded.

const tailChunk = 256 << 10 // bytes read per backwards step

// lineCount returns the number of records in path.
//
// Rotated generations never change once written, so their count is cached by
// path. The live file only ever grows (until it rotates, which shrinks it), so
// its count is maintained by counting just the bytes appended since last time.
func (s *Store) lineCount(path string) int {
	if path != s.path {
		if n, ok := s.rotatedLines[path]; ok {
			return n
		}
		b, err := readMaybeGzip(path)
		if err != nil {
			return 0
		}
		n := bytes.Count(b, []byte{'\n'})
		if s.rotatedLines == nil {
			s.rotatedLines = map[string]int{}
		}
		s.rotatedLines[path] = n
		return n
	}

	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	size := fi.Size()
	if size < s.countedBytes { // rotated out from under us: start over
		s.countedBytes, s.countedLines = 0, 0
	}
	if size == s.countedBytes {
		return s.countedLines
	}
	f, err := os.Open(path)
	if err != nil {
		return s.countedLines
	}
	defer f.Close()
	if _, err := f.Seek(s.countedBytes, 0); err != nil {
		return s.countedLines
	}
	buf := make([]byte, 64<<10)
	added := 0
	for {
		n, err := f.Read(buf)
		if n > 0 {
			added += bytes.Count(buf[:n], []byte{'\n'})
		}
		if err != nil {
			break
		}
	}
	s.countedBytes, s.countedLines = size, s.countedLines+added
	return s.countedLines
}

// matchingLine reports whether a raw JSONL line can possibly match needle. It is
// deliberately a substring test over the whole line: cheap, and a false positive
// only costs one JSON decode (which then filters properly).
func matchingLine(line []byte, needle string) bool {
	if needle == "" {
		return true
	}
	return bytes.Contains(bytes.ToLower(line), []byte(needle))
}

// recordMatches applies the real (field-scoped) filter.
func recordMatches(r Record, needle string) bool {
	if needle == "" {
		return true
	}
	return contains(r.Host, needle) || contains(r.Dest, needle) ||
		contains(r.Process, needle) || contains(r.Outbound, needle)
}

// scanNewestFirst walks one file from the end, returning up to want matching
// records (newest first) and the total number of matches in the file. When
// needle is empty and want is satisfied, it stops early and total is left at -1
// for the caller to fill from lineCount — that early exit is the whole point.
func (s *Store) scanNewestFirst(path, needle string, want int) (recs []Record, total int) {
	if needle == "" {
		recs = s.tailRecords(path, want)
		return recs, -1
	}
	b, err := readMaybeGzip(path)
	if err != nil {
		return nil, 0
	}
	lines := bytes.Split(b, []byte{'\n'})
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if len(line) == 0 || !matchingLine(line, needle) {
			continue
		}
		var r Record
		if json.Unmarshal(line, &r) != nil {
			continue
		}
		s.parsed++
		if !recordMatches(r, needle) {
			continue
		}
		total++
		if len(recs) < want {
			recs = append(recs, r)
		}
	}
	return recs, total
}

// tailRecords returns up to want newest records from path without reading more
// of it than needed. Compressed generations can't be read backwards, so those
// are decompressed once and walked in reverse.
func (s *Store) tailRecords(path string, want int) []Record {
	if want <= 0 {
		return nil
	}
	if strings.HasSuffix(path, ".gz") {
		b, err := readMaybeGzip(path)
		if err != nil {
			return nil
		}
		return s.decodeReverse(bytes.Split(b, []byte{'\n'}), want)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil
	}

	size := fi.Size()
	var tail []byte
	for read := int64(0); read < size; {
		step := int64(tailChunk)
		if read+step > size {
			step = size - read
		}
		buf := make([]byte, step)
		if _, err := f.ReadAt(buf, size-read-step); err != nil {
			break
		}
		tail = append(buf, tail...)
		read += step
		// The first line in the window may be truncated; only trust whole lines
		// unless we have reached the start of the file.
		lines := bytes.Split(tail, []byte{'\n'})
		if read < size {
			lines = lines[1:]
		}
		if countNonEmpty(lines) >= want || read >= size {
			return s.decodeReverse(lines, want)
		}
	}
	return s.decodeReverse(bytes.Split(tail, []byte{'\n'}), want)
}

// decodeReverse decodes up to want records from lines, newest (last) first.
func (s *Store) decodeReverse(lines [][]byte, want int) []Record {
	out := make([]Record, 0, want)
	for i := len(lines) - 1; i >= 0 && len(out) < want; i-- {
		if len(lines[i]) == 0 {
			continue
		}
		var r Record
		if json.Unmarshal(lines[i], &r) != nil {
			continue
		}
		s.parsed++
		out = append(out, r)
	}
	return out
}

func countNonEmpty(lines [][]byte) int {
	n := 0
	for _, l := range lines {
		if len(l) > 0 {
			n++
		}
	}
	return n
}
