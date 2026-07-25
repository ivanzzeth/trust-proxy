package api

import (
	"encoding/json"
	"net/http"
)

// decodeListReq decodes the shared {type,value} body used by whitelist/
// blacklist/directlist add/remove handlers. ok=false means a 400 was already
// written and the caller should return immediately.
func decodeListReq(w http.ResponseWriter, r *http.Request) (typ, value string, ok bool) {
	var req struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Value == "" {
		writeErr(w, http.StatusBadRequest, "type and value are required")
		return "", "", false
	}
	return req.Type, req.Value, true
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
