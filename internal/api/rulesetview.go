package api

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Decoded rule-set contents are cached in-memory (a remote .srs can be several
// MB / 100k+ entries — decode once, then paginate/search cheaply).
type rsCacheEntry struct {
	entries []ruleset.Entry
	at      time.Time
}

var (
	rsMu    sync.Mutex
	rsCache = map[string]rsCacheEntry{}
)

// handleRuleSetRules returns the decoded, searchable, paginated contents of one
// imported rule-set (GET /api/rulesets/{tag}/rules?q=&offset=&limit=). Never
// dumps everything at once — geosite-cn alone is 100k+ entries.
func (s *Server) handleRuleSetRules(w http.ResponseWriter, r *http.Request) {
	if s.rs == nil {
		writeErr(w, http.StatusServiceUnavailable, "rulesets not available")
		return
	}
	tag := r.PathValue("tag")
	var found *apitypes.RuleSet
	for _, rs := range s.rs.Get().Sets {
		if rs.Tag == tag {
			cp := rs
			found = &cp
			break
		}
	}
	if found == nil {
		writeErr(w, http.StatusNotFound, "rule-set not found")
		return
	}
	entries, err := decodeCached(*found)
	if err != nil {
		// Common in CN when the source is a GFW-blocked github URL fetched direct.
		writeErr(w, http.StatusBadGateway, "decode rule-set: "+err.Error())
		return
	}

	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	filtered := entries
	if q != "" {
		filtered = filtered[:0:0]
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.Value), q) {
				filtered = append(filtered, e)
			}
		}
	}
	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tag":     tag,
		"count":   len(entries), // full size of the rule-set
		"total":   total,        // after search filter
		"offset":  offset,
		"limit":   limit,
		"entries": filtered[offset:end],
	})
}

func decodeCached(rs apitypes.RuleSet) ([]ruleset.Entry, error) {
	key := rs.Tag + "|" + rs.URL + "|" + rs.Path
	rsMu.Lock()
	if c, ok := rsCache[key]; ok && time.Since(c.at) < 10*time.Minute {
		e := c.entries
		rsMu.Unlock()
		return e, nil
	}
	rsMu.Unlock()

	entries, err := ruleset.Decode(rs, nil) // nil => direct fetch
	if err != nil {
		return nil, err
	}
	rsMu.Lock()
	rsCache[key] = rsCacheEntry{entries: entries, at: time.Now()}
	rsMu.Unlock()
	return entries, nil
}
