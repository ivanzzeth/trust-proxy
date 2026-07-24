package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivanzzeth/trust-proxy/internal/blacklist"
	"github.com/ivanzzeth/trust-proxy/internal/customrules"
	"github.com/ivanzzeth/trust-proxy/internal/detect"
	"github.com/ivanzzeth/trust-proxy/internal/directlist"
	"github.com/ivanzzeth/trust-proxy/internal/gateway"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// selftest is an in-binary end-to-end test of the core routing engine. It needs
// no internet and no real proxy: it stands up a local "origin" server and a
// local "node" upstream proxy that tags traffic it forwards (X-Via: node), then
// drives the REAL gateway (internal/gateway.Manager) through every core scenario
// and checks that each request egresses the right way — via the node, direct,
// or blocked. Copy the binary into a VM and run `trust-proxy selftest`; a
// non-zero exit means a core behavior regressed.
var selftestCmd = &cobra.Command{
	Use:    "selftest",
	Short:  "Run the in-binary end-to-end test of the routing engine (offline)",
	Hidden: true,
	RunE:   func(cmd *cobra.Command, args []string) error { return runSelftest() },
}

// freePort grabs an OS-assigned free TCP port.
func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func runSelftest() error {
	directPort, nodeOriginPort := freePort(), freePort()
	nodePort := freePort()
	mixedPort, clashPort := freePort(), freePort()

	// Two "internet" origins: whichever one answers tells us the egress path.
	// The direct outbound reaches directPort; the node upstream splices to
	// nodeOriginPort. Each just returns its own tag as the body.
	tagServer := func(port int, tag string) *http.Server {
		s := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, tag)
		})}
		go s.ListenAndServe()
		return s
	}
	directOrigin := tagServer(directPort, "direct")
	defer directOrigin.Close()
	nodeOrigin := tagServer(nodeOriginPort, "node")
	defer nodeOrigin.Close()

	// node upstream: an HTTP proxy standing in for the exit node. sing-box's http
	// outbound uses CONNECT, so we splice the tunnel to the node-origin (any
	// request that goes through the node lands there and reads "node").
	nodeOriginAddr := fmt.Sprintf("127.0.0.1:%d", nodeOriginPort)
	nodeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dst, err := net.Dial("tcp", nodeOriginAddr)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		if r.Method == http.MethodConnect {
			hj, ok := w.(http.Hijacker)
			if !ok {
				dst.Close()
				return
			}
			src, _, err := hj.Hijack()
			if err != nil {
				dst.Close()
				return
			}
			_, _ = src.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			go func() { _, _ = io.Copy(dst, src); dst.Close() }()
			_, _ = io.Copy(src, dst)
			src.Close()
			return
		}
		// plain proxied request: forward to the node-origin.
		defer dst.Close()
		out, err := http.NewRequest(r.Method, "http://"+nodeOriginAddr+r.URL.Path, r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
	node := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", nodePort), Handler: nodeHandler}
	go node.ListenAndServe()
	defer node.Close()

	dataDir, err := os.MkdirTemp("", "tp-selftest-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dataDir)

	// base config: mixed inbound + clash api (no secret) on test ports.
	baseCfg := fmt.Sprintf(`{
	  "log": {"level": "error"},
	  "experimental": {"clash_api": {"external_controller": "127.0.0.1:%d", "secret": ""}},
	  "inbounds": [{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":%d}],
	  "outbounds": [{"type":"direct","tag":"direct"},{"type":"block","tag":"blocked"},{"type":"selector","tag":"proxy","outbounds":["direct"]}],
	  "route": {"rules":[{"action":"sniff"},{"network":["tcp","udp"],"action":"route","outbound":"blocked"}], "final":"blocked"}
	}`, clashPort, mixedPort)
	cfgPath := filepath.Join(dataDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(baseCfg), 0o644); err != nil {
		return err
	}

	// Every test domain resolves to the origin so the DIRECT outbound can reach
	// it; the node path forwards to the origin regardless.
	hostRecords := map[string][]string{}
	for _, d := range []string{"allow.tp", "deny.tp", "direct.tp", "evil.tp", "np.tp", "cdirect.tp", "cproxy.tp", "cblock.tp", "cnode.tp", "www.gstatic.com"} {
		hostRecords[d] = []string{"127.0.0.1"}
	}
	dns := apitypes.DNSConfig{
		Servers: []apitypes.DNSServer{{Tag: "hosts", Type: "hosts", Records: hostRecords}},
		Final:   "hosts",
	}

	engine := detect.New(500)
	mgr := gateway.NewManager(cfgPath, dataDir, whitelist.Rules{}, engine, "")
	mgr.SetInitialDNS(dns)
	// The exit node: an http outbound at our tagging upstream.
	nodeOB, _ := json.Marshal(map[string]any{"type": "http", "tag": "NODE", "server": "127.0.0.1", "server_port": nodePort})
	mgr.SetInitialNodes([]apitypes.Node{{Tag: "NODE", Protocol: "http", Server: "127.0.0.1", Port: nodePort, Outbound: nodeOB}})
	// A manual selector group over the node so `proxy` egress is deterministic
	// (no urltest health-check dependency on real internet).
	mgr.SetInitialProxyGroups(proxygroups.Config{Groups: []proxygroups.Group{
		{Name: "g", Type: "select", Filter: "manual", Nodes: []string{"NODE"}},
	}})
	if err := mgr.Start(); err != nil {
		return fmt.Errorf("gateway start: %w", err)
	}
	defer mgr.Close()
	time.Sleep(400 * time.Millisecond)
	selectProxyGroup(clashPort, "g") // point the proxy selector at the node group

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 6 * time.Second}
	// get fetches domain through the gateway; returns "node"/"direct" or "" on a
	// blocked/failed connection.
	get := func(domain string) string {
		resp, err := client.Get(fmt.Sprintf("http://%s:%d/", domain, directPort))
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(b))
	}

	empty := whitelist.Rules{}
	reset := func() {
		_ = mgr.SetWhitelist(empty)
		_ = mgr.SetBlacklist(blacklist.Rules{})
		_ = mgr.SetDirectList(directlist.Rules{})
		_ = mgr.SetCustomRules(customrules.Rules{})
		selectProxyGroup(clashPort, "g")
	}

	type step struct {
		name   string
		setup  func()
		domain string
		want   string // "node" | "direct" | "" (blocked)
	}
	steps := []step{
		{"default-deny blocks unlisted", func() {}, "deny.tp", ""},
		{"whitelist domain egresses via node", func() { _ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}}) }, "allow.tp", "node"},
		{"no-proxy list egresses direct", func() { _ = mgr.SetDirectList(directlist.Rules{Domains: []string{"np.tp"}}) }, "np.tp", "direct"},
		{"blacklist beats whitelist", func() {
			_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"evil.tp"}})
			_ = mgr.SetBlacklist(blacklist.Rules{Domains: []string{"evil.tp"}})
		}, "evil.tp", ""},
		{"custom rule: direct", func() {
			_ = mgr.SetCustomRules(customrules.Rules{Rules: []apitypes.CustomRule{{Match: "domain_suffix", Value: "cdirect.tp", Action: "direct", Enabled: true}}})
		}, "cdirect.tp", "direct"},
		{"custom rule: proxy (via node)", func() {
			_ = mgr.SetCustomRules(customrules.Rules{Rules: []apitypes.CustomRule{{Match: "domain_suffix", Value: "cproxy.tp", Action: "proxy", Node: "g", Enabled: true}}})
		}, "cproxy.tp", "node"},
		{"custom rule: block", func() {
			_ = mgr.SetCustomRules(customrules.Rules{Rules: []apitypes.CustomRule{{Match: "domain_suffix", Value: "cblock.tp", Action: "block", Enabled: true}}})
		}, "cblock.tp", ""},
		{"custom rule: node target", func() {
			_ = mgr.SetCustomRules(customrules.Rules{Rules: []apitypes.CustomRule{{Match: "domain_suffix", Value: "cnode.tp", Action: "node", Node: "NODE", Enabled: true}}})
		}, "cnode.tp", "node"},
	}

	pass, fail := 0, 0
	check := func(name, want, got string) {
		ok := want == got
		label := map[string]string{"node": "node", "direct": "direct", "": "blocked"}
		if ok {
			pass++
			fmt.Printf("  PASS  %-40s -> %s\n", name, label[got])
		} else {
			fail++
			fmt.Printf("  FAIL  %-40s want=%s got=%s\n", name, label[want], label[got])
		}
	}

	fmt.Println("== manual mode ==")
	for _, s := range steps {
		reset()
		s.setup()
		selectProxyGroup(clashPort, "g")
		time.Sleep(150 * time.Millisecond)
		check(s.name, s.want, get(s.domain))
	}

	// system mode: same egress path + sets the OS proxy. Just confirm egress.
	fmt.Println("== system mode ==")
	reset()
	_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}})
	if err := mgr.SetMode(gateway.ModeSystem); err != nil {
		fmt.Printf("  SKIP  system mode (%v)\n", err)
	} else {
		selectProxyGroup(clashPort, "g")
		time.Sleep(200 * time.Millisecond)
		check("whitelist via node (system)", "node", get("allow.tp"))
		_ = mgr.SetMode(gateway.ModeManual)
	}

	// tun mode: needs root; loopback traffic isn't captured by TUN, so we can
	// only assert the gateway builds + starts in TUN mode (config accepted).
	fmt.Println("== tun mode ==")
	if os.Geteuid() != 0 {
		fmt.Println("  SKIP  tun mode (needs root)")
	} else if err := mgr.SetMode(gateway.ModeTUN); err != nil {
		fail++
		fmt.Printf("  FAIL  tun mode start: %v\n", err)
	} else {
		pass++
		fmt.Println("  PASS  tun mode: gateway built + started")
		_ = mgr.SetMode(gateway.ModeManual)
	}

	fmt.Printf("\n%d passed, %d failed\n", pass, fail)
	if fail > 0 {
		return fmt.Errorf("selftest: %d scenario(s) failed", fail)
	}
	return nil
}

// selectProxyGroup points the `proxy` selector at the named group via the Clash API.
func selectProxyGroup(clashPort int, name string) {
	body, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("http://127.0.0.1:%d/proxies/proxy", clashPort), strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}
