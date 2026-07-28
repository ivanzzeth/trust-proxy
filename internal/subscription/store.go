// Package subscription fetches, parses and persists proxy-provider
// subscriptions. Storage is a JSON file for now (SQLite, à la s-ui, can come
// later); the logic of "fetch URL -> decode -> parse nodes" mirrors s-ui.
package subscription

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Store is a file-backed set of subscriptions, safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	data map[string]*apitypes.Subscription
	http *http.Client

	// ensureReachable, if set, is called with a subscription URL's hostname
	// before every fetch. See SetEnsureReachable.
	ensureReachable func(host string) error
}

// NewStore opens (or creates) the store at path.
func NewStore(path string) (*Store, error) {
	s := &Store{
		path: path,
		data: map[string]*apitypes.Subscription{},
		http: newUTLSClient(""),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetEnsureReachable registers a hook run (best-effort) before every URL
// fetch, given the subscription URL's hostname.
//
// Why this exists: in TUN mode the gateway captures ALL of this machine's
// outbound traffic at the network layer — including this Store's own HTTP
// fetches, which have nothing to do with sing-box's internal dialer. Without
// this hook, a subscription refresh gets captured by our own TUN and routed
// out through whichever proxy node currently happens to be applied, instead
// of this machine's real network path. Some subscription providers actively
// detect "this request looks like it's coming via a VPN/proxy" (by source IP
// reputation) and refuse to serve real node data — which looks exactly like
// a fetch failure with no obvious cause. The fix isn't to escape our own TUN
// capture (that runs into OS/firewall-level interface-binding quirks that
// proved unreliable in testing) — it's to make sure OUR OWN fetch traffic,
// once captured like everything else, is routed DIRECT rather than through a
// remote proxy node. Direct egress already reliably reaches the real
// internet under this gateway's TUN capture (that's how any other
// permitted-direct traffic works); routing our own control-plane fetches the
// same way sidesteps the "looks like a VPN" problem entirely. The callback is
// expected to permit + route-direct the host on the live gateway (see
// cmd/serve.go).
func (s *Store) SetEnsureReachable(fn func(host string) error) {
	s.mu.Lock()
	s.ensureReachable = fn
	s.mu.Unlock()
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []*apitypes.Subscription
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, sub := range list {
		s.data[sub.ID] = sub
	}
	return nil
}

func (s *Store) save() error {
	list := s.listLocked()
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

func (s *Store) listLocked() []apitypes.Subscription {
	out := make([]apitypes.Subscription, 0, len(s.data))
	for _, sub := range s.data {
		out = append(out, *sub)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// List returns all subscriptions (without the heavy Nodes slice trimmed;
// callers that only need counts can ignore Nodes).
func (s *Store) List() []apitypes.Subscription {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked()
}

// Get returns one subscription by id.
func (s *Store) Get(id string) (apitypes.Subscription, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.data[id]
	if !ok {
		return apitypes.Subscription{}, false
	}
	return *sub, true
}

func idFor(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:])[:12]
}

// hostOf extracts the hostname from a subscription URL (empty for file://
// URLs or anything unparseable — those don't need ensureReachable).
func hostOf(rawURL string) string {
	u, err := neturl.Parse(rawURL)
	if err != nil || u.Scheme == "file" {
		return ""
	}
	return u.Hostname()
}

// DefaultUserAgent is what we send when fetching a subscription. Many airports
// gate by UA (a generic curl UA gets a 403), so we default to a common client.
const DefaultUserAgent = "clash-verge/v2.4.2"

// Add registers a subscription and immediately refreshes it. If content is set
// it's a manual/pasted node list (no network fetch); otherwise url is fetched
// (via, if set, routes the fetch through a socks5://|http:// proxy). The id is
// derived from the content or URL so re-adding is idempotent.
func (s *Store) Add(name, url, userAgent, via, content string) (apitypes.Subscription, error) {
	id := idFor(url)
	if content != "" {
		id = idFor("manual:" + content)
	}
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	s.mu.Lock()
	if _, exists := s.data[id]; !exists {
		s.data[id] = &apitypes.Subscription{ID: id, Name: name, URL: url, Content: content, UserAgent: userAgent, Via: via}
	} else {
		if name != "" {
			s.data[id].Name = name
		}
		s.data[id].UserAgent = userAgent
		s.data[id].Via = via
		if content != "" {
			s.data[id].Content = content
		}
	}
	s.mu.Unlock()
	return s.Refresh(id)
}

// SetApplied marks id as applied without clearing others. Multiple applied
// subscriptions are merged into the live proxy group (see AppliedNodes) so
// several airports can back each other up. Call ClearApplied to drop one.
//
// Profiles still snapshot only the first applied id today; activating a
// profile will re-assert a single SubID until profiles grow a multi-id field.
func (s *Store) SetApplied(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.data[id]
	if !ok {
		return fmt.Errorf("subscription %q not found", id)
	}
	sub.Applied = true
	return s.save()
}

// ClearApplied removes id from the applied set. The caller is expected to
// re-Apply AppliedNodes() (or an empty list) so the data plane matches.
func (s *Store) ClearApplied(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.data[id]
	if !ok {
		return fmt.Errorf("subscription %q not found", id)
	}
	sub.Applied = false
	return s.save()
}

// ClearAllApplied clears every applied flag. Used when activating a profile
// that still snapshots a single SubID — the live set must shrink to that one
// (or none) so flags match the nodes ApplyProfile just loaded.
func (s *Store) ClearAllApplied() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, sub := range s.data {
		if sub.Applied {
			sub.Applied = false
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.save()
}

// AppliedNodes returns every node from every applied subscription, in a
// stable order (by subscription name — same order as List). Tag
// collisions across subscriptions are fine: gateway.memberTags renames
// duplicates with -2/-3.
func (s *Store) AppliedNodes() []apitypes.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	subs := s.listLocked()
	var out []apitypes.Node
	for i := range subs {
		if !subs[i].Applied {
			continue
		}
		out = append(out, subs[i].Nodes...)
	}
	return out
}

// Delete removes a subscription.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[id]; !ok {
		return fmt.Errorf("subscription %q not found", id)
	}
	delete(s.data, id)
	return s.save()
}

// Refresh fetches the URL, parses nodes and persists the result. A fetch/parse
// failure is recorded on LastError but does not delete the subscription.
func (s *Store) Refresh(id string) (apitypes.Subscription, error) {
	s.mu.Lock()
	sub, ok := s.data[id]
	url, ua, via, content := "", "", "", ""
	if ok {
		url, ua, via, content = sub.URL, sub.UserAgent, sub.Via, sub.Content
	}
	s.mu.Unlock()
	if !ok {
		return apitypes.Subscription{}, fmt.Errorf("subscription %q not found", id)
	}

	var (
		nodes []apitypes.Node
		ferr  error
	)
	if content != "" {
		nodes = Parse([]byte(content)) // manual: parse pasted text, no fetch
	} else {
		s.mu.Lock()
		ensure := s.ensureReachable
		s.mu.Unlock()
		if ensure != nil {
			if host := hostOf(url); host != "" {
				if err := ensure(host); err != nil {
					// Best-effort: still attempt the fetch even if we
					// couldn't (re)permit the host — it may already be
					// reachable for other reasons (manual/system mode, an
					// existing whitelist entry, etc).
					_ = err
				}
			}
		}
		nodes, ferr = s.fetchAndParse(url, ua, via)
	}

	s.mu.Lock()
	sub = s.data[id]
	sub.UpdatedAt = time.Now().Format(time.RFC3339)
	switch {
	case ferr != nil:
		sub.LastError = ferr.Error()
	case len(nodes) == 0:
		// The fetch "succeeded" (no ferr) but parsed to zero nodes — almost
		// always a bad response (empty body, captive portal, an incompatible
		// format, a flaky airport endpoint), not the subscriber intentionally
		// emptying their node list. Never overwrite a previously-good node
		// list with this: applying it would silently collapse the proxy
		// group to direct-only. Surface it as an error either way so a
		// brand-new subscription that never had nodes doesn't sit there
		// silently at 0 with no explanation.
		if len(sub.Nodes) > 0 {
			ferr = fmt.Errorf("refresh returned 0 nodes; kept previous %d node(s)", len(sub.Nodes))
		} else {
			ferr = fmt.Errorf("fetched OK but found 0 parseable nodes — check the subscription URL/format")
		}
		sub.LastError = ferr.Error()
	default:
		sub.LastError = ""
		sub.Nodes = nodes
		sub.NodeCount = len(nodes)
	}
	result := *sub
	saveErr := s.save()
	s.mu.Unlock()

	if ferr != nil {
		return result, ferr
	}
	return result, saveErr
}

func (s *Store) fetchAndParse(url, userAgent, via string) ([]apitypes.Node, error) {
	// Local import: bypass the network entirely (useful when the airport's WAF
	// blocks non-official clients — point at a clash-verge profile instead).
	if path, ok := strings.CutPrefix(url, "file://"); ok {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return Parse(b), nil
	}

	client := s.http
	if via != "" {
		client = newUTLSClient(via) // per-subscription egress proxy
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription fetch: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return Parse(body), nil
}
