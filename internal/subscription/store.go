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
	"os"
	"path/filepath"
	"sort"
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
}

// NewStore opens (or creates) the store at path.
func NewStore(path string) (*Store, error) {
	s := &Store{
		path: path,
		data: map[string]*apitypes.Subscription{},
		http: &http.Client{Timeout: 30 * time.Second},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
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
	return os.WriteFile(s.path, b, 0o644)
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

// DefaultUserAgent is what we send when fetching a subscription. Many airports
// gate by UA (a generic curl UA gets a 403), so we default to a common client.
const DefaultUserAgent = "clash-verge/v2.0.0"

// Add registers a subscription (id derived from URL, so re-adding is
// idempotent) and immediately refreshes it.
func (s *Store) Add(name, url, userAgent string) (apitypes.Subscription, error) {
	id := idFor(url)
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	s.mu.Lock()
	if _, exists := s.data[id]; !exists {
		s.data[id] = &apitypes.Subscription{ID: id, Name: name, URL: url, UserAgent: userAgent}
	} else {
		if name != "" {
			s.data[id].Name = name
		}
		s.data[id].UserAgent = userAgent
	}
	s.mu.Unlock()
	return s.Refresh(id)
}

// SetApplied marks id as the applied subscription (and clears the flag on the
// others, since the data plane runs one subscription at a time).
func (s *Store) SetApplied(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[id]; !ok {
		return fmt.Errorf("subscription %q not found", id)
	}
	for k, sub := range s.data {
		sub.Applied = k == id
	}
	return s.save()
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
	url, ua := "", ""
	if ok {
		url, ua = sub.URL, sub.UserAgent
	}
	s.mu.Unlock()
	if !ok {
		return apitypes.Subscription{}, fmt.Errorf("subscription %q not found", id)
	}

	nodes, ferr := s.fetchAndParse(url, ua)

	s.mu.Lock()
	sub = s.data[id]
	sub.UpdatedAt = time.Now().Format(time.RFC3339)
	if ferr != nil {
		sub.LastError = ferr.Error()
	} else {
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

func (s *Store) fetchAndParse(url, userAgent string) ([]apitypes.Node, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.http.Do(req)
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
