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
	"sync"
)

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
	return os.WriteFile(path, b, 0o644)
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
