// Package liststore holds the small, data-shape-independent helpers shared by
// the file-backed string-list stores (whitelist/blacklist/directlist): sorted
// dedup insert/remove, a generic filter-and-count, JSON persistence, and a
// lock/mutate/save/unlock wrapper. Stores with materially different
// validation shapes (ruleset, customrules) are intentionally not folded in
// here — only the parts that were byte-for-byte identical across the three.
package liststore

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// NoteKey builds the map key used in Rules.Notes: "<dim>:<value>".
// dim is the list dimension (domain|ip|process|device|keyword|regex) — the
// same strings the API mutation body uses for "type".
func NoteKey(dim, value string) string {
	return dim + ":" + value
}

// CloneNotes returns a shallow copy of notes (nil stays nil).
func CloneNotes(notes map[string]string) map[string]string {
	if notes == nil {
		return nil
	}
	out := make(map[string]string, len(notes))
	for k, v := range notes {
		out[k] = v
	}
	return out
}

// SetNote writes or clears a remark. Empty note deletes the key. Returns the
// (possibly newly allocated) map; never returns a non-nil empty map — callers
// get nil so JSON omits the field.
func SetNote(notes map[string]string, dim, value, note string) map[string]string {
	key := NoteKey(dim, value)
	note = strings.TrimSpace(note)
	if note == "" {
		if notes == nil {
			return nil
		}
		delete(notes, key)
		if len(notes) == 0 {
			return nil
		}
		return notes
	}
	if notes == nil {
		notes = map[string]string{}
	}
	notes[key] = note
	return notes
}

// ClearNote drops the remark for dim/value if present.
func ClearNote(notes map[string]string, dim, value string) map[string]string {
	return SetNote(notes, dim, value, "")
}

// PruneNotes drops remark keys whose dim prefix matches dim and whose value
// is not in keep. Used after sanitize drops invalid entries so orphan notes
// don't linger on disk.
func PruneNotes(notes map[string]string, dim string, keep []string) map[string]string {
	if notes == nil {
		return nil
	}
	alive := make(map[string]struct{}, len(keep))
	for _, v := range keep {
		alive[v] = struct{}{}
	}
	prefix := dim + ":"
	for k := range notes {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if _, ok := alive[k[len(prefix):]]; !ok {
			delete(notes, k)
		}
	}
	if len(notes) == 0 {
		return nil
	}
	return notes
}

// NoteOf returns the remark for dim/value, or "" if none.
func NoteOf(notes map[string]string, dim, value string) string {
	if notes == nil {
		return ""
	}
	return notes[NoteKey(dim, value)]
}

// ValidCIDR reports whether s is a usable ip_cidr entry (a CIDR or a bare IP).
func ValidCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}

// Add appends v to list if not already present, keeping the list sorted.
func Add(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	list = append(list, v)
	sort.Strings(list)
	return list
}

// Remove drops v from list.
func Remove(list []string, v string) []string {
	out := list[:0:0]
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// Filter keeps only the elements of list for which keep returns true,
// incrementing *removed once per dropped element.
func Filter(list []string, keep func(string) bool, removed *int) []string {
	out := list[:0:0]
	for _, x := range list {
		if keep(x) {
			out = append(out, x)
		} else {
			*removed++
		}
	}
	return out
}

// SaveJSON marshals v as indented JSON to path, creating parent dirs as needed.
func SaveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Mutate runs fn under mu (which must mutate *data in place), persists *data
// to path as JSON, and returns a snapshot — the lock/mutate/save/unlock shape
// every Add*/Remove*/Set method in these stores follows. snapshot must return
// a deep-enough copy that the caller can't mutate the store's internals.
func Mutate[T any](mu *sync.Mutex, path string, data *T, fn func(), snapshot func(T) T) (T, error) {
	mu.Lock()
	fn()
	snap := snapshot(*data)
	err := SaveJSON(path, *data)
	mu.Unlock()
	return snap, err
}
