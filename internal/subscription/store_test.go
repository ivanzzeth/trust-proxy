package subscription

import (
	"os"
	"path/filepath"
	"testing"
)

const oneNodeYAML = `proxies:
  - { name: "node1", type: "ss", server: "1.2.3.4", port: 8388, cipher: "aes-256-gcm", password: "pw" }
`

// TestRefreshDoesNotClobberGoodNodesWithEmptyResult locks in the fix for a
// real-world bug: a subscription whose refresh "succeeds" (no fetch error)
// but parses to zero nodes must NOT overwrite a previously-good node list —
// applying an empty node list collapses the gateway's proxy group to
// direct-only, silently breaking every route that depended on a real node.
func TestRefreshDoesNotClobberGoodNodesWithEmptyResult(t *testing.T) {
	subPath := filepath.Join(t.TempDir(), "sub.yaml")
	if err := os.WriteFile(subPath, []byte(oneNodeYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	fileURL := "file://" + subPath

	s, err := NewStore(filepath.Join(t.TempDir(), "subscriptions.json"))
	if err != nil {
		t.Fatal(err)
	}

	sub, err := s.Add("test", fileURL, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if sub.NodeCount != 1 || len(sub.Nodes) != 1 {
		t.Fatalf("expected 1 node after initial add, got %+v", sub)
	}

	// Simulate the subscription link going bad (empty/unparseable response)
	// on a later refresh, without changing the URL (same subscription id).
	if err := os.WriteFile(subPath, []byte("not a valid subscription body"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub2, err := s.Refresh(sub.ID)
	if err == nil {
		t.Fatal("expected Refresh to report an error when it yields 0 nodes")
	}
	if sub2.NodeCount != 1 || len(sub2.Nodes) != 1 || sub2.Nodes[0].Tag != sub.Nodes[0].Tag {
		t.Fatalf("previously-good nodes must survive a 0-node refresh, got %+v", sub2)
	}
	if sub2.LastError == "" {
		t.Fatal("expected LastError to explain the 0-node refresh")
	}

	// The persisted copy must match (not just the in-memory return value).
	again, ok := s.Get(sub.ID)
	if !ok || len(again.Nodes) != 1 {
		t.Fatalf("persisted subscription lost its nodes: %+v ok=%v", again, ok)
	}
}

// TestEnsureReachableCalledWithHostBeforeFetch locks in the fix for the
// "subscription fetch gets captured by our own TUN and looks like a VPN
// request" bug: Refresh must call the ensureReachable hook with the
// subscription URL's hostname before every network fetch.
func TestEnsureReachableCalledWithHostBeforeFetch(t *testing.T) {
	subPath := filepath.Join(t.TempDir(), "sub.yaml")
	if err := os.WriteFile(subPath, []byte(oneNodeYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(filepath.Join(t.TempDir(), "subscriptions.json"))
	if err != nil {
		t.Fatal(err)
	}

	var gotHosts []string
	s.SetEnsureReachable(func(host string) error {
		gotHosts = append(gotHosts, host)
		return nil
	})

	// file:// URLs bypass the network entirely, so the hook must NOT fire —
	// there's no fetch traffic to protect.
	if _, err := s.Add("local", "file://"+subPath, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if len(gotHosts) != 0 {
		t.Fatalf("expected no ensureReachable calls for a file:// subscription, got %v", gotHosts)
	}

	sub, err := s.Add("remote", "https://example.test/sub?token=abc", "", "", "")
	_ = sub
	_ = err // network call will fail in this offline test; we only care about the pre-fetch hook
	if len(gotHosts) != 1 || gotHosts[0] != "example.test" {
		t.Fatalf("expected ensureReachable(\"example.test\") before the fetch, got %v", gotHosts)
	}
}

// TestAddSurfacesErrorWhenBrandNewSubscriptionHasZeroNodes ensures a fresh
// subscription that never had any nodes still gets a clear LastError instead
// of silently sitting at node_count=0 with no explanation.
func TestAddSurfacesErrorWhenBrandNewSubscriptionHasZeroNodes(t *testing.T) {
	subPath := filepath.Join(t.TempDir(), "sub.yaml")
	if err := os.WriteFile(subPath, []byte("not a valid subscription body"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(filepath.Join(t.TempDir(), "subscriptions.json"))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := s.Add("test", "file://"+subPath, "", "", "")
	if err == nil {
		t.Fatal("expected Add to report an error for a subscription with 0 parseable nodes")
	}
	if sub.NodeCount != 0 {
		t.Fatalf("expected 0 nodes, got %d", sub.NodeCount)
	}
	if sub.LastError == "" {
		t.Fatal("expected LastError to be set so the user knows why it's empty")
	}
}
