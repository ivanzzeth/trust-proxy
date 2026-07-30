package gateway

import (
	"encoding/json"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivanzzeth/trust-proxy/internal/detect"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

const listenBase = `{
  "experimental": {"clash_api": {"external_controller": "127.0.0.1:21586", "secret": ""}},
  "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 21584}],
  "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "blocked"}],
  "route": {"rules": [], "final": "direct"}
}`

// mixedInbound returns the listen point the merged config actually declares.
func mixedInbound(t *testing.T, mode string, bind apitypes.InboundListen) (string, int) {
	t.Helper()
	merged, err := buildMergedConfig([]byte(listenBase), nil, whitelist.Rules{Domains: []string{"ok.com"}},
		blacklist.Rules{}, quarantine.List{}, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{},
		mode, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, bind,
		apitypes.TUNConfig{Stack: "gvisor"}, nil, nil, "proxy", "", "s", "", t.TempDir())
	if err != nil {
		t.Fatalf("buildMergedConfig: %v", err)
	}
	var cfg struct {
		Inbounds []struct {
			Type   string `json:"type"`
			Listen string `json:"listen"`
			Port   int    `json:"listen_port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, in := range cfg.Inbounds {
		if in.Type == "mixed" {
			return in.Listen, in.Port
		}
	}
	t.Fatal("no mixed inbound in the merged config")
	return "", 0
}

// The setting has to reach the data plane, in every capture mode. TUN keeps the
// mixed inbound alongside the tun one (so 127.0.0.1:21584 stays usable there),
// which means a listen point that only applies in manual mode would look
// correct right up until someone turns on TUN.
func TestInboundListenReachesTheDataPlaneInEveryMode(t *testing.T) {
	for _, mode := range Modes {
		t.Run(mode, func(t *testing.T) {
			listen, port := mixedInbound(t, mode, apitypes.InboundListen{Listen: "0.0.0.0", Port: 1080})
			if listen != "0.0.0.0" || port != 1080 {
				t.Fatalf("mixed inbound bound %s:%d, want 0.0.0.0:1080", listen, port)
			}
		})
	}
}

// Zero fields mean "no opinion". A machine that has never touched this setting
// must bind exactly where its own config.json says — including a hand-edited
// non-default port, which a store that resolved zeroes to 127.0.0.1:21584 would
// silently move out from under every client on that machine.
func TestUnsetListenKeepsWhateverTheBaseConfigDeclares(t *testing.T) {
	listen, port := mixedInbound(t, ModeManual, apitypes.InboundListen{})
	if listen != "127.0.0.1" || port != 21584 {
		t.Fatalf("unset bind produced %s:%d, want the base config's 127.0.0.1:21584", listen, port)
	}
}

// Half an opinion is still an opinion: setting only the port must not reset the
// address (and vice versa), or "let me move the port" would quietly also expose
// the proxy — or un-expose it — depending on which half the caller sent.
func TestPartialListenOverridesOnlyWhatWasSet(t *testing.T) {
	const custom = `{
	  "experimental": {"clash_api": {"external_controller": "127.0.0.1:21586", "secret": ""}},
	  "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "192.168.1.5", "listen_port": 7890}],
	  "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "blocked"}],
	  "route": {"rules": [], "final": "direct"}
	}`
	get := func(bind apitypes.InboundListen) (string, int) {
		t.Helper()
		merged, err := buildMergedConfig([]byte(custom), nil, whitelist.Rules{Domains: []string{"ok.com"}},
			blacklist.Rules{}, quarantine.List{}, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{},
			ModeManual, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{}, bind,
			apitypes.TUNConfig{}, nil, nil, "proxy", "", "s", "", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Inbounds []struct {
				Type   string `json:"type"`
				Listen string `json:"listen"`
				Port   int    `json:"listen_port"`
			} `json:"inbounds"`
		}
		if err := json.Unmarshal(merged, &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg.Inbounds[0].Listen, cfg.Inbounds[0].Port
	}

	if l, p := get(apitypes.InboundListen{Port: 1080}); l != "192.168.1.5" || p != 1080 {
		t.Fatalf("port-only override gave %s:%d, want 192.168.1.5:1080", l, p)
	}
	if l, p := get(apitypes.InboundListen{Listen: "0.0.0.0"}); l != "0.0.0.0" || p != 7890 {
		t.Fatalf("address-only override gave %s:%d, want 0.0.0.0:7890", l, p)
	}
}

// Management-port exemption (the L0 floor that keeps a remote box reachable)
// keys off the API port, not the proxy port — moving the proxy must not disturb
// it. Asserted because the two are adjacent numbers and easy to conflate.
func TestMovingTheProxyDoesNotDisturbTheManagementFloor(t *testing.T) {
	merged, err := buildMergedConfig([]byte(listenBase), nil, whitelist.Rules{Domains: []string{"ok.com"}},
		blacklist.Rules{}, quarantine.List{}, directlist.Rules{}, customrules.Rules{}, proxygroups.Config{},
		ModeManual, ruleset.Sets{}, apitypes.DNSConfig{}, apitypes.InboundAuth{},
		apitypes.InboundListen{Listen: "0.0.0.0", Port: 1080},
		apitypes.TUNConfig{}, nil, []int{22, 21585}, "proxy", "", "s", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(merged) {
		t.Fatal("merged config is not valid JSON")
	}
	var cfg struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range cfg.Route.Rules {
		ports, ok := r["source_port"].([]any)
		if !ok {
			continue
		}
		for _, p := range ports {
			if n, ok := p.(float64); ok && int(n) == 21585 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("management port exemption for 21585 vanished when the proxy moved")
	}
}

// The guard exists because a bad listen point does not fail. The rebuild
// succeeds and the gateway happily serves an address nobody is pointed at:
// every client on the machine is configured for the old one, so the failure is
// total, silent, and may well have taken away the channel you would fix it
// through.
//
// Asserting that the OLD port comes back is the whole test. An implementation
// that only re-saves the value, or that arms a timer it never applies, leaves
// the new port serving and passes any check that just looks at the store.
func TestInboundListenGuardRevertsWhenNotConfirmed(t *testing.T) {
	dir := t.TempDir()
	oldPort, newPort := freePort(t), freePort(t)
	cfgPath := filepath.Join(dir, "config.json")
	writeBase(t, cfgPath, oldPort)

	mgr := NewManager(cfgPath, dir, whitelist.Rules{Domains: []string{"example.com"}}, detect.New(64), "", "")
	if err := mgr.Start(); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if !accepts(oldPort) {
		t.Fatal("not listening on the original port; nothing below would mean anything")
	}

	var reverted atomic.Value
	mgr.SetInboundRevertHook(func(l apitypes.InboundListen) { reverted.Store(l) })

	prev, err := mgr.SetInboundListenGuarded(apitypes.InboundListen{Port: newPort}, 700*time.Millisecond)
	if err != nil {
		t.Fatalf("SetInboundListenGuarded: %v", err)
	}
	if prev != (apitypes.InboundListen{}) {
		t.Fatalf("previous listen point reported as %+v, want the unset value", prev)
	}
	if !waitAccepts(newPort) {
		t.Fatalf("the new port %d never came up", newPort)
	}
	if _, left, armed := mgr.PendingInboundRevert(); !armed || left < 0 {
		t.Fatal("no pending revert reported while the guard is armed")
	}

	if !waitAccepts(oldPort) {
		t.Fatalf("the guard expired without restoring the original port %d", oldPort)
	}
	if mgr.InboundListen() != (apitypes.InboundListen{}) {
		t.Fatalf("manager still holds %+v after the revert", mgr.InboundListen())
	}
	// The store has to be rolled back too, or the file keeps claiming a port the
	// data plane no longer serves and the next restart applies the very setting
	// the guard just rejected.
	if got, ok := reverted.Load().(apitypes.InboundListen); !ok || got != (apitypes.InboundListen{}) {
		t.Fatalf("revert hook got %v (ok=%v), want the previous value so the store can follow", got, ok)
	}
	if _, _, armed := mgr.PendingInboundRevert(); armed {
		t.Fatal("guard still reports armed after it fired")
	}
}

// Confirming means "I can still reach it": the new port stays and no revert
// fires afterwards.
func TestConfirmInboundListenKeepsTheNewPort(t *testing.T) {
	dir := t.TempDir()
	oldPort, newPort := freePort(t), freePort(t)
	cfgPath := filepath.Join(dir, "config.json")
	writeBase(t, cfgPath, oldPort)

	mgr := NewManager(cfgPath, dir, whitelist.Rules{Domains: []string{"example.com"}}, detect.New(64), "", "")
	if err := mgr.Start(); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	if _, err := mgr.SetInboundListenGuarded(apitypes.InboundListen{Port: newPort}, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	mgr.ConfirmInboundListen()
	time.Sleep(900 * time.Millisecond) // past when the guard would have fired

	if !accepts(newPort) {
		t.Fatalf("confirmed port %d is not listening", newPort)
	}
	if got := mgr.InboundListen(); got.Port != newPort {
		t.Fatalf("manager holds %+v after confirm, want port %d", got, newPort)
	}
	if _, _, armed := mgr.PendingInboundRevert(); armed {
		t.Fatal("a confirmed change still has a revert armed")
	}
}

// Two dead-man's switches can be armed at once, and confirming one must not
// settle the other — they answer different questions ("can you still reach the
// console?" vs "can your clients still reach the proxy?") and a shared timer
// would let a mode confirmation silently adopt an unreachable port.
func TestModeAndInboundGuardsAreIndependent(t *testing.T) {
	dir := t.TempDir()
	oldPort, newPort := freePort(t), freePort(t)
	cfgPath := filepath.Join(dir, "config.json")
	writeBase(t, cfgPath, oldPort)

	mgr := NewManager(cfgPath, dir, whitelist.Rules{Domains: []string{"example.com"}}, detect.New(64), "", "")
	if err := mgr.Start(); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	if _, err := mgr.SetInboundListenGuarded(apitypes.InboundListen{Port: newPort}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.SetModeGuarded(ModeSystem, 30*time.Second); err != nil {
		t.Skipf("system mode unavailable in this environment: %v", err)
	}

	mgr.ConfirmMode()
	if _, _, armed := mgr.PendingInboundRevert(); !armed {
		t.Fatal("confirming the mode also settled the inbound guard")
	}
	mgr.ConfirmInboundListen()
	if _, _, armed := mgr.PendingRevert(); armed {
		t.Fatal("the mode guard should already have been confirmed")
	}
}
