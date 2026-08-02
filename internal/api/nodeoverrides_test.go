package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivanzzeth/trust-proxy/internal/nodeoverride"
	"github.com/ivanzzeth/trust-proxy/internal/subscription"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

type fakeNOApplier struct {
	tags []string
}

func (f *fakeNOApplier) SetDisabledNodes(tags []string) error {
	f.tags = append([]string(nil), tags...)
	return nil
}

func TestNodeOverrides_DisableEnable(t *testing.T) {
	dir := t.TempDir()
	noStore, err := nodeoverride.NewStore(filepath.Join(dir, "no.json"))
	if err != nil {
		t.Fatal(err)
	}
	applier := &fakeNOApplier{}
	s := &Server{nodeOverrides: noStore, noApplier: applier}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/nodes/disable", strings.NewReader(`{"tag":"新加坡 C"}`))
	s.handleDisableNode(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(applier.tags) != 1 || applier.tags[0] != "新加坡 C" {
		t.Fatalf("applier got %v", applier.tags)
	}

	rec = httptest.NewRecorder()
	s.handleEnableNode(rec, httptest.NewRequest(http.MethodPost, "/api/nodes/enable", strings.NewReader(`{"tag":"新加坡 C"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(applier.tags) != 0 {
		t.Fatalf("after enable applier=%v", applier.tags)
	}
}

func TestNodeOverrides_GetListsJunkFromApplied(t *testing.T) {
	dir := t.TempDir()
	subPath := filepath.Join(dir, "subs.json")
	list := []apitypes.Subscription{{
		ID: "abc", Name: "t", Applied: true, NodeCount: 2,
		Nodes: []apitypes.Node{
			{
				Tag: "跳转域名{请勿连接}:x", Protocol: "shadowsocks",
				Server: "123.123.213.213", Port: 53,
				Outbound: json.RawMessage(`{"type":"shadowsocks","tag":"跳转域名{请勿连接}:x","server":"123.123.213.213","server_port":53,"method":"aes-128-gcm","password":"x"}`),
			},
			{
				Tag: "台湾", Protocol: "shadowsocks",
				Server: "tw.example", Port: 12001,
				Outbound: json.RawMessage(`{"type":"shadowsocks","tag":"台湾","server":"tw.example","server_port":12001,"method":"aes-128-gcm","password":"x"}`),
			},
		},
	}}
	b, _ := json.Marshal(list)
	if err := os.WriteFile(subPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	sub, err := subscription.NewStore(subPath)
	if err != nil {
		t.Fatal(err)
	}
	noStore, _ := nodeoverride.NewStore(filepath.Join(dir, "no.json"))
	s := &Server{store: sub, nodeOverrides: noStore}
	rec := httptest.NewRecorder()
	s.handleGetNodeOverrides(rec, httptest.NewRequest(http.MethodGet, "/api/node-overrides", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var view apitypes.NodeOverrides
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Junk) != 1 || !strings.Contains(view.Junk[0].Tag, "跳转") {
		t.Fatalf("junk=%v", view.Junk)
	}
	var live, junk int
	for _, n := range view.Nodes {
		switch n.Status {
		case apitypes.NodeStatusLive:
			live++
		case apitypes.NodeStatusJunk:
			junk++
		}
	}
	if live != 1 || junk != 1 {
		t.Fatalf("nodes live=%d junk=%d view=%+v", live, junk, view.Nodes)
	}
}
