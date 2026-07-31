package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Who may reach which route, declared once per route.
//
// This used to be computed: a path was matched against a list of public paths and
// a list of read-only-for-users *prefixes*, and whatever fell through was admin.
// Reading it, that sounds like a table. It behaved like four overlapping rules,
// and every one of them turned out to be wrong somewhere:
//
//   - the reverse-proxy prefix was stripped before the lookup, so a forwarded
//     request could match a public path and skip authentication entirely — while
//     the proxy went on to inject the stored probe credential;
//   - "/api/proxies" as a prefix also granted /api/proxies/{name}/delay, which
//     dials wherever the caller points it, outside every policy layer;
//   - the Origin check was skipped for public levels, leaving the account-creating
//     endpoints with no CSRF defence;
//   - "/api/logs" and the aggregate */stats endpoints are gateway-wide and
//     unscoped, and sat next to their per-caller siblings on the same list.
//
// None of those are individually subtle. They are what a prefix list does: it
// answers a question nobody asked it, about routes that did not exist when it was
// written. So the level is now stated for each route, resolved through the same
// pattern matching the mux itself uses, and anything undeclared is admin.
//
// Adding a route means adding a line here. TestEveryRouteHasADeclaredLevelAndViceVersa
// fails if the two sets drift, in either direction.
func routeLevels() map[string]access {
	return map[string]access{
		// --- public: reachable by anyone who can reach the port -----------------
		// Deliberately tiny, and all four mutations are Origin-checked.
		"GET /api/health":          accessPublic, // liveness; the desktop shell polls it before login
		"GET /api/auth/state":      accessPublic, // "must I bootstrap, may I register?"
		"POST /api/auth/bootstrap": accessPublic, // create the first admin (further guarded in the handler)
		"POST /api/auth/login":     accessPublic,
		"POST /api/auth/logout":    accessPublic,
		"POST /api/auth/register":  accessPublic, // the store refuses unless an admin opened signup
		// Redeeming a console ticket is how a browser with nothing becomes logged
		// in, so it cannot require a credential. Safe because a ticket is
		// single-use, lives 60s, and is only ever issued to an authenticated caller
		// — which is why minting one (POST) is not public.
		"GET /api/auth/ticket": accessPublic,

		// --- any logged-in account ---------------------------------------------
		// Observability about the caller's own traffic, and the one write a client
		// has: asking for a destination to be permitted. That request creates a
		// disabled rule and grants nothing until an admin approves it.
		"GET /api/status":       accessUser,
		"GET /api/auth/me":      accessUser,
		"POST /api/auth/ticket": accessUser,
		"GET /api/connections":  accessUser, // scoped in the handler
		"GET /api/traffic":      accessUser,
		"GET /api/events":       accessUser, // scoped
		"GET /api/detections":   accessUser, // scoped
		"GET /api/history":      accessUser, // scoped
		"GET /api/proxies":      accessUser,
		// The score badge sits beside the delay badge on the same page, and
		// describes the same nodes /api/proxies already names. No policy and no
		// per-caller data is in it; resetting the observations is a write, so
		// that half is admin.
		"GET /api/proxy-scores":     accessUser,
		"POST /api/permit-requests": accessUser,
		"GET /api/permit-requests":  accessUser, // scoped to the caller's own

		// --- admin --------------------------------------------------------------
		// Everything that changes what the gateway enforces, plus the reads that
		// are not scoped to one caller.
		//
		// GET /api/logs is the whole gateway log stream: every account's
		// destinations, in real time. The */stats endpoints are gateway-wide
		// aggregates — top talkers, detection counts — while the list endpoints on
		// the same prefixes are per-caller. /api/effective-rules and /api/rules
		// render the policy, which internal/users promises a client cannot read.
		// /api/proxies/{name}/delay dials a caller-supplied URL through a chosen
		// outbound, bypassing route.rules completely.
		"GET /api/logs":                 accessAdmin,
		"GET /api/history/stats":        accessAdmin,
		"GET /api/detections/stats":     accessAdmin,
		"GET /api/dns-queries/stats":    accessAdmin,
		"GET /api/netcheck":             accessAdmin,
		"GET /api/fingerprints":         accessAdmin,
		"GET /api/effective-rules":      accessAdmin,
		"GET /api/rules":                accessAdmin,
		"GET /api/proxies/{name}/delay": accessAdmin,
		"PUT /api/proxies/select":       accessAdmin,

		"GET /api/mode":                     accessAdmin,
		"POST /api/mode":                    accessAdmin,
		"POST /api/mode/confirm":            accessAdmin,
		"GET /api/posture":                  accessAdmin,
		"PUT /api/posture":                  accessAdmin,
		"POST /api/autoblock":               accessAdmin,
		"GET /api/clash-mode":               accessAdmin,
		"PUT /api/clash-mode":               accessAdmin,
		"POST /api/doctor/nftables/install": accessAdmin,

		"GET /api/subscriptions":               accessAdmin,
		"POST /api/subscriptions":              accessAdmin,
		"DELETE /api/subscriptions/{id}":       accessAdmin,
		"GET /api/subscriptions/{id}/export":   accessAdmin,
		"POST /api/subscriptions/{id}/refresh": accessAdmin,
		"POST /api/subscriptions/{id}/apply":   accessAdmin,
		"POST /api/subscriptions/{id}/unapply": accessAdmin,
		"GET /api/proxy-gen/protocols":         accessAdmin,
		"POST /api/proxy-gen":                  accessAdmin,

		"DELETE /api/connections/{id}": accessAdmin,
		"DELETE /api/connections":      accessAdmin,

		"GET /api/detection-config":   accessAdmin,
		"PUT /api/detection-config":   accessAdmin,
		"GET /api/quarantine":         accessAdmin,
		"DELETE /api/quarantine":      accessAdmin,
		"POST /api/quarantine/permit": accessAdmin,

		"GET /api/whitelist":     accessAdmin,
		"POST /api/whitelist":    accessAdmin,
		"DELETE /api/whitelist":  accessAdmin,
		"GET /api/blacklist":     accessAdmin,
		"POST /api/blacklist":    accessAdmin,
		"DELETE /api/blacklist":  accessAdmin,
		"GET /api/directlist":    accessAdmin,
		"POST /api/directlist":   accessAdmin,
		"DELETE /api/directlist": accessAdmin,

		"GET /api/customrules":                   accessAdmin,
		"POST /api/customrules":                  accessAdmin,
		"PATCH /api/customrules/{id}":            accessAdmin,
		"DELETE /api/customrules/{id}":           accessAdmin,
		"POST /api/customrules/{id}/move":        accessAdmin,
		"GET /api/customrules/packs/catalog":     accessAdmin,
		"POST /api/customrules/packs/apply":      accessAdmin,
		"PATCH /api/customrules/packs/{name}":    accessAdmin,
		"DELETE /api/customrules/packs/{name}":   accessAdmin,
		"POST /api/permit-requests/{id}/approve": accessAdmin,
		"DELETE /api/permit-requests/{id}":       accessAdmin,

		"GET /api/proxygroups":          accessAdmin,
		"PUT /api/proxygroups":          accessAdmin,
		"POST /api/proxy-scores/reset":  accessAdmin,
		"GET /api/rulesets":             accessAdmin,
		"GET /api/rulesets/catalog":     accessAdmin,
		"GET /api/rulesets/{tag}/rules": accessAdmin,
		"POST /api/rulesets":            accessAdmin,
		"PATCH /api/rulesets/{tag}":     accessAdmin,
		"DELETE /api/rulesets/{tag}":    accessAdmin,

		"GET /api/nodes":         accessAdmin,
		"POST /api/nodes":        accessAdmin,
		"PATCH /api/nodes/{id}":  accessAdmin,
		"DELETE /api/nodes/{id}": accessAdmin,
		// The relay itself. Its level is not this one: a forwarded request is judged
		// by what it asks for (see requirement), floored at accessUser because it
		// injects the target gateway's stored token.
		"/api/nodes/{id}/{rest...}": accessUser,

		"GET /api/dns":   accessAdmin,
		"PUT /api/dns":   accessAdmin,
		"GET /api/final": accessAdmin,
		"PUT /api/final": accessAdmin,
		"GET /api/tun":   accessAdmin,
		"PUT /api/tun":   accessAdmin,

		// Where the proxy listens, and how much of the gateway's own output stays
		// on disk. Admin on both halves including the reads: the listen point
		// tells a caller which interface to reach the proxy on, and the retention
		// policy is machine plumbing no client has a use for.
		"GET /api/inbound":          accessAdmin,
		"PUT /api/inbound":          accessAdmin,
		"POST /api/inbound/confirm": accessAdmin,
		"GET /api/retention":        accessAdmin,
		"PUT /api/retention":        accessAdmin,
		// Built-in values only — no machine state, but it enumerates every knob
		// the gateway has, which is a policy shape clients are not shown.
		"GET /api/defaults": accessAdmin,

		"GET /api/endpoints":               accessAdmin,
		"POST /api/endpoints":              accessAdmin,
		"PATCH /api/endpoints/{tag}":       accessAdmin,
		"DELETE /api/endpoints/{tag}":      accessAdmin,
		"GET /api/profiles":                accessAdmin,
		"POST /api/profiles":               accessAdmin,
		"POST /api/profiles/{id}/activate": accessAdmin,
		"DELETE /api/profiles/{id}":        accessAdmin,

		"GET /api/auth/settings": accessAdmin,
		"PUT /api/auth/settings": accessAdmin,
		// Users are admin, with one exception applied against the authenticated
		// identity rather than the path: your own password and your own API keys.
		// See isSelfService — a path cannot tell whether {id} is you.
		"GET /api/users":                         accessAdmin,
		"POST /api/users":                        accessAdmin,
		"PATCH /api/users/{id}":                  accessAdmin,
		"DELETE /api/users/{id}":                 accessAdmin,
		"POST /api/users/{id}/apikeys":           accessAdmin,
		"DELETE /api/users/{id}/apikeys/{keyID}": accessAdmin,
	}
}

// levelMux resolves a request to the route pattern that would serve it, using the
// stdlib's own matching — precedence, wildcards, method specificity and all.
// Reimplementing that matching here is how the prefix list drifted from the
// routes in the first place.
var (
	levelMuxOnce sync.Once
	levelMux     *http.ServeMux
	levels       map[string]access
)

func accessLookup() (*http.ServeMux, map[string]access) {
	levelMuxOnce.Do(func() {
		levels = routeLevels()
		levelMux = http.NewServeMux()
		for pattern := range levels {
			p := pattern
			levelMux.Handle(p, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		}
	})
	return levelMux, levels
}

// levelOf returns the declared level for the route that would serve method+path,
// or accessAdmin when nothing declares one.
//
// Admin for the unknown is the only safe default: a handler added without a line
// in routeLevels then fails visibly for whoever is missing access, rather than
// quietly opening up for everybody.
func levelOf(method, path string) access {
	mux, table := accessLookup()
	probe := httptest.NewRequest(method, path, nil)
	_, pattern := mux.Handler(probe)
	if lvl, ok := table[pattern]; ok {
		return lvl
	}
	return accessAdmin
}

// nodeProxyTarget reports the path a /api/nodes/{id}/… request is forwarded as.
func nodeProxyTarget(p string) (string, bool) {
	if !strings.HasPrefix(p, "/api/nodes/") {
		return "", false
	}
	rest := strings.TrimPrefix(p, "/api/nodes/")
	i := strings.Index(rest, "/")
	if i < 0 {
		return "", false // /api/nodes/{id} itself: not the relay
	}
	return "/api" + rest[i:], true
}

// servedPatterns lists the route patterns the server actually registers, for the
// test that keeps routeLevels and the mux the same set.
func servedPatterns() map[string]bool {
	out := map[string]bool{}
	for _, p := range registeredPatterns {
		out[p] = true
	}
	return out
}

// registeredPatterns is appended to by Server.route as the mux is built. It is
// package-level rather than per-server because the routes are the same for every
// instance, and because the drift test must be able to see them without
// constructing a fully wired server.
var (
	registeredMu       sync.Mutex
	registeredPatterns []string
)

// route registers a handler and records the pattern, so nothing can be served
// without appearing in the set the access table is checked against.
func (s *Server) route(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	registeredMu.Lock()
	if !patternKnown(pattern) {
		registeredPatterns = append(registeredPatterns, pattern)
	}
	registeredMu.Unlock()
	mux.HandleFunc(pattern, h)
}

func patternKnown(pattern string) bool {
	for _, p := range registeredPatterns {
		if p == pattern {
			return true
		}
	}
	return false
}
