package api

import (
	"encoding/json"
	"net/http"
)

// listMutateReq is the shared body for whitelist/blacklist/directlist add/
// remove. Note is optional: present on add to set/update a remark (empty
// string clears); ignored on remove (the remark is dropped with the entry).
type listMutateReq struct {
	Type  string  `json:"type"`
	Value string  `json:"value"`
	Note  *string `json:"note"`
}

// decodeListReq decodes the shared {type,value,note?} body. ok=false means a
// 400 was already written and the caller should return immediately.
func decodeListReq(w http.ResponseWriter, r *http.Request) (req listMutateReq, ok bool) {
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Value == "" {
		writeErr(w, http.StatusBadRequest, "type and value are required")
		return listMutateReq{}, false
	}
	return req, true
}

// noteArgs turns an optional *string into the variadic form the stores expect:
// nil → omit (preserve existing remark on re-add); non-nil → set/clear.
func noteArgs(note *string) []string {
	if note == nil {
		return nil
	}
	return []string{*note}
}

// applyOrRollback applies rules to the running gateway via apply (nil = no
// applier wired, a no-op). On failure it restores prev into the store via set
// and writes a 502; the caller should return without writing its own success
// response. Returns true if it already wrote a response.
func applyOrRollback[T any](w http.ResponseWriter, rules, prev T, apply func(T) error, set func(T) (T, error), errPrefix string) bool {
	if apply == nil {
		return false
	}
	if err := apply(rules); err != nil {
		_, _ = set(prev) // un-poison the store so it matches the running plane
		writeErr(w, http.StatusBadGateway, errPrefix+err.Error())
		return true
	}
	return false
}

// nonNil returns an empty slice instead of nil so it serializes as [] rather
// than null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
