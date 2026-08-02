package ruleset

import (
	"context"
	"io"
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

// maxRuleSetProbeBytes caps what a probe will read. The catalog's .srs files are
// tens of kilobytes; the largest (geosite-geolocation-!cn) is a few hundred. 32 MiB
// is far past anything legitimate and only there so a source answering with a
// stream cannot hold a posture switch open.
const maxRuleSetProbeBytes = 32 << 20

// Sources lists everywhere a catalog entry can be fetched from, best-known
// first. Duplicates and empties are dropped.
//
// Mirrors (jsdelivr) come before the catalog primary (raw.githubusercontent):
// when both answer, GitHub-first used to win and then stall mid-body inside the
// GFW — sing-box hung for minutes while the mirror would have finished in ~1s.
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
	add(e.URL)
	return out
}

// PreferredURL returns the catalog URL a fresh seed / pack import should write:
// the jsdelivr mirror when present, else the primary. Callers that can probe
// should still Prefer PickReachableWith(Sources(...)); this is the offline default.
func PreferredURL(e apitypes.RuleSetCatalogEntry) string {
	if e.Mirror != "" {
		return e.Mirror
	}
	return e.URL
}

// isCatalogSource reports whether url is one of the known fetch locations for
// this catalog entry (primary, mirror, or a derived jsdelivr front-end).
// ResolveSources must rewrite any of these — not only the primary — or a box
// already on a dead GitHub URL / a stale mirror host never heals.
func isCatalogSource(e apitypes.RuleSetCatalogEntry, url string) bool {
	if url == "" {
		return false
	}
	for _, u := range Sources(e) {
		if u == url {
			return true
		}
	}
	return false
}

// PickReachable returns the candidate that can be *downloaded* first, or "" when
// none can.
//
// A race, not a sequence: the failure being designed around is a blackholed TCP
// connect, which costs the full timeout, and trying four of those in a row would
// stall a posture switch for the better part of a minute. Whichever source finishes
// first is also, usefully, the fastest one from here.
//
// The whole object, not a range request. This asked for `Range: bytes=0-0` — one
// byte — reasoning that it proves the object is there and costs nothing. The
// cheapness was the bug: the failure being selected against is a path that
// completes a handshake, returns a header and then stalls partway through the body,
// which is what raw.githubusercontent.com does from inside the GFW, and a one-byte
// range request is the one thing such a path can still satisfy.
//
// Measured on a real machine: every source answered 206 in under a second to a
// range request, so the probe kept the primary URL, and sing-box then timed out
// fetching five of thirteen rule sets from it — while the mirror the catalog has
// always carried would have worked, and the probe had just voted against it.
//
// These files are tens of kilobytes. Downloading one is the question actually being
// asked, and it costs nothing worth saving.
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
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				results <- result{u, false}
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 400 {
				results <- result{u, false}
				return
			}
			// Read it to the end, inside the same budget. A stalling body fails here,
			// which is the entire point; a body cut short by the deadline fails as an
			// io error rather than looking like a short file.
			//
			// Bounded, because a source that answers with something enormous should not
			// be able to hold a posture switch open: no rule set is anywhere near this,
			// so hitting the cap means the answer is not a rule set.
			n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxRuleSetProbeBytes+1))
			switch {
			case err != nil:
				results <- result{u, false}
			case n == 0:
				results <- result{u, false} // a 200 with no body is not a rule set
			case n > maxRuleSetProbeBytes:
				results <- result{u, false}
			default:
				results <- result{u, true}
			}
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
	return ResolveSourcesWith(sets, func(probe map[string]string) map[string]bool {
		return ReachableHosts(probe, budget)
	})
}

// ResolveSourcesWith is ResolveSources with the reachability check injected, so a
// test can decide what answers without reaching the network — otherwise it would be
// measuring GitHub's availability rather than this code.
func ResolveSourcesWith(sets []apitypes.RuleSet, reach func(probe map[string]string) map[string]bool) []string {
	// One representative URL per host, so a probe proves a real object is served
	// and not merely that something accepts connections there.
	probe := map[string]string{}
	for i := range sets {
		rs := &sets[i]
		if rs.Type != "remote" || !rs.Enabled {
			continue
		}
		if entry, ok := CatalogByTag(rs.Tag); ok && isCatalogSource(entry, rs.URL) {
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
	reachable := reach(probe)

	var disabled []string
	for i := range sets {
		rs := &sets[i]
		if rs.Type != "remote" || !rs.Enabled {
			continue
		}
		entry, ok := CatalogByTag(rs.Tag)
		if !ok || !isCatalogSource(entry, rs.URL) {
			continue // hand-entered URL: theirs, not ours
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

// ReachableHosts probes one URL per host, all at once, within a single budget.
func ReachableHosts(probe map[string]string, budget time.Duration) map[string]bool {
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

// PickReachableWith chooses among candidates using an injected reachability check.
//
// The same seam ResolveSourcesWith uses, for the single-set case: importing one rule
// set has to make the same decision as seeding a dozen, and a test must be able to
// make it without asking the actual internet.
func PickReachableWith(cands []string, reach func(probe map[string]string) map[string]bool) string {
	if len(cands) == 0 {
		return ""
	}
	probe := map[string]string{}
	for _, u := range cands {
		if h := hostOf(u); h != "" {
			if _, seen := probe[h]; !seen {
				probe[h] = u
			}
		}
	}
	ok := reach(probe)
	for _, u := range cands {
		if ok[hostOf(u)] {
			return u
		}
	}
	return ""
}
