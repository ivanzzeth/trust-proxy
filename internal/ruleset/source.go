package ruleset

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Where a public rule set is actually fetched from.
//
// The catalog has carried a jsdelivr `Mirror` beside every GitHub URL from the
// start, with a comment saying it is the one that works from inside the GFW —
// and nothing ever read it. Seeding Split therefore pointed every rule set at
// raw.githubusercontent.com, sing-box could not fetch a single one on a machine
// that cannot reach GitHub, and the box refused to start. On a gateway with no
// exit node yet that is not an edge case, it is the first thing a new user in
// China does: there is no node, so the download cannot go through the proxy
// either, and the only way out is a mirror.
//
// sing-box performs the fetch itself, so the choice has to be made when the
// config is built — we can only hand it a URL. Hence: probe, then decide.

// mirrorHosts are jsdelivr front-ends. One being blocked or rate-limited does
// not mean the others are, and they serve byte-identical files.
var mirrorHosts = []string{"cdn.jsdelivr.net", "testingcf.jsdelivr.net", "gcore.jsdelivr.net"}

// Sources lists everywhere a catalog entry can be fetched from, best-known
// first. Duplicates and empties are dropped.
func Sources(e apitypes.RuleSetCatalogEntry) []string {
	var out []string
	seen := map[string]bool{}
	add := func(u string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	add(e.URL)
	add(e.Mirror)
	// The catalog stores one mirror; the other jsdelivr front-ends are the same
	// path on a different host, so they come for free rather than needing three
	// more fields per entry.
	if e.Mirror != "" {
		for _, h := range mirrorHosts {
			if i := strings.Index(e.Mirror, "://"); i > 0 {
				rest := e.Mirror[i+3:]
				if j := strings.Index(rest, "/"); j > 0 {
					add(e.Mirror[:i+3] + h + rest[j:])
				}
			}
		}
	}
	return out
}

// PickReachable returns the candidate that answers first, or "" when none do.
//
// A race, not a sequence: the failure mode being designed around is a blackholed
// TCP connect, which costs the full timeout, and trying four of those in a row
// would stall a posture switch for the better part of a minute. Whichever host
// answers first is also, usefully, the fastest one from here.
//
// A HEAD may be refused by a CDN that is perfectly willing to GET, so this asks
// for the first byte instead — enough to prove the object is really there,
// cheap enough not to matter.
func PickReachable(cands []string, budget time.Duration) string {
	if len(cands) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	type result struct {
		url string
		ok  bool
	}
	results := make(chan result, len(cands))
	var wg sync.WaitGroup
	for _, u := range cands {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				results <- result{u, false}
				return
			}
			req.Header.Set("Range", "bytes=0-0")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				results <- result{u, false}
				return
			}
			_ = resp.Body.Close()
			results <- result{u, resp.StatusCode < 400}
		}(u)
	}
	go func() { wg.Wait(); close(results) }()

	for r := range results {
		if r.ok {
			return r.url // cancel() on return kills the losers
		}
	}
	return ""
}

// ResolveSources rewrites each rule set to a source this machine can actually
// reach, and disables the ones it cannot. It returns the tags it disabled.
//
// Disabling rather than dropping is the point: injectRuleSets skips disabled
// entries, so the box starts either way, and the rule set stays visible with its
// URL intact — enable it once there is a node and the download will go through
// the proxy. Dropping them would leave the user with a policy quietly missing
// pieces they never knew were meant to be there.
//
// Only remote sets whose tag is in the catalog are touched; a URL somebody typed
// themselves is theirs.
// budget is for the whole call, not per rule set: reachability is a property of
// the *host*, not of each path on it, so a dozen catalog entries need three or
// four probes between them rather than a dozen. Probing per set was 13 × 6s and
// the CLI gave up before the API answered.
func ResolveSources(sets []apitypes.RuleSet, budget time.Duration) []string {
	// One representative URL per host, so a probe proves a real object is served
	// and not merely that something accepts connections there.
	probe := map[string]string{}
	for i := range sets {
		rs := &sets[i]
		if rs.Type != "remote" || !rs.Enabled {
			continue
		}
		if entry, ok := CatalogByTag(rs.Tag); ok && entry.URL == rs.URL {
			for _, u := range Sources(entry) {
				if h := hostOf(u); h != "" {
					if _, seen := probe[h]; !seen {
						probe[h] = u
					}
				}
			}
		}
	}
	if len(probe) == 0 {
		return nil
	}
	reachable := reachableHosts(probe, budget)

	var disabled []string
	for i := range sets {
		rs := &sets[i]
		if rs.Type != "remote" || !rs.Enabled {
			continue
		}
		entry, ok := CatalogByTag(rs.Tag)
		if !ok || entry.URL != rs.URL {
			continue // hand-entered or already customised: theirs, not ours
		}
		picked := ""
		for _, u := range Sources(entry) {
			if reachable[hostOf(u)] {
				picked = u
				break
			}
		}
		if picked != "" {
			rs.URL = picked
			continue
		}
		rs.Enabled = false
		disabled = append(disabled, rs.Tag)
	}
	return disabled
}

// reachableHosts probes one URL per host, all at once, within a single budget.
func reachableHosts(probe map[string]string, budget time.Duration) map[string]bool {
	type result struct {
		host string
		ok   bool
	}
	results := make(chan result, len(probe))
	for host, u := range probe {
		go func(host, u string) {
			results <- result{host, PickReachable([]string{u}, budget) != ""}
		}(host, u)
	}
	out := map[string]bool{}
	for range probe {
		r := <-results
		out[r.host] = r.ok
	}
	return out
}

func hostOf(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	rest := u[i+3:]
	if j := strings.Index(rest, "/"); j > 0 {
		return rest[:j]
	}
	return rest
}
