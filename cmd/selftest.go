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
	"github.com/ivanzzeth/trust-proxy/internal/subscription"
	"github.com/ivanzzeth/trust-proxy/internal/whitelist"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// selftestSubFile, when set, runs the LIVE section: apply the real node(s) from
// this clash-yaml file and fetch real sites through them, asserting real data.
var selftestSubFile string

func init() {
	selftestCmd.Flags().StringVar(&selftestSubFile, "sub-file", "", "clash-yaml file with real node(s): also run the live real-data test through them")
}

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
	for _, d := range []string{
		"allow.tp", "deny.tp", "deny2.tp", "direct.tp", "np.tp", "evil.tp", "evilg.tp",
		"track-me.tp", "reblock.tp", "sub.wild.tp",
		"cdirect.tp", "cproxy.tp", "cblock.tp", "cnode.tp", "kw-host.tp", "rex.tp", "ord.tp",
		"www.gstatic.com",
		// node-exit.tp is the dial address of our mock upstream. It resolves to
		// 127.0.0.1 via hosts, but must NOT be a literal loopback IP — otherwise
		// Auto treats the live node as a local agent (WARP-style) and the
		// loopback-exclusion regression can't tell dead-local from NODE.
		"node-exit.tp",
	} {
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
	nodeOB, _ := json.Marshal(map[string]any{"type": "http", "tag": "NODE", "server": "node-exit.tp", "server_port": nodePort})
	mgr.SetInitialNodes([]apitypes.Node{{Tag: "NODE", Protocol: "http", Server: "node-exit.tp", Port: nodePort, Outbound: nodeOB}})
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

	selfExe, _ := os.Executable()
	selfProc := filepath.Base(selfExe)

	reset := func() {
		_ = mgr.SetWhitelist(whitelist.Rules{})
		_ = mgr.SetBlacklist(blacklist.Rules{})
		_ = mgr.SetDirectList(directlist.Rules{})
		_ = mgr.SetCustomRules(customrules.Rules{})
		setClashMode(clashPort, "Rule")
		selectProxyGroup(clashPort, "g")
	}

	pass, fail := 0, 0
	label := map[string]string{"node": "node", "direct": "direct", "": "blocked"}
	check := func(name, want, got string) {
		if want == got {
			pass++
			fmt.Printf("  PASS  %-42s -> %s\n", name, label[got])
		} else {
			fail++
			fmt.Printf("  FAIL  %-42s want=%s got=%s\n", name, label[want], label[got])
		}
	}
	// run reconfigures policy, waits for the rebuild, and asserts the egress path.
	run := func(name string, setup func(), target, want string) {
		reset()
		setup()
		selectProxyGroup(clashPort, "g")
		time.Sleep(150 * time.Millisecond)
		check(name, want, get(target))
	}
	cr := func(rules ...apitypes.CustomRule) func() {
		return func() { _ = mgr.SetCustomRules(customrules.Rules{Rules: rules}) }
	}
	rule := func(match, value, action, node string) apitypes.CustomRule {
		return apitypes.CustomRule{Match: match, Value: value, Action: action, Node: node, Enabled: true}
	}

	fmt.Println("== ACL: allow / deny ==")
	run("default-deny blocks unlisted", func() {}, "deny.tp", "")
	run("whitelist domain -> node", func() { _ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}}) }, "allow.tp", "node")
	run("whitelist wildcard *.wild.tp -> node", func() { _ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"*.wild.tp"}}) }, "sub.wild.tp", "node")
	run("whitelist IP -> node", func() { _ = mgr.SetWhitelist(whitelist.Rules{IPs: []string{"203.0.113.5/32"}}) }, "203.0.113.5", "node")

	fmt.Println("== egress: no-proxy / private ==")
	run("no-proxy domain -> direct", func() { _ = mgr.SetDirectList(directlist.Rules{Domains: []string{"np.tp"}}) }, "np.tp", "direct")
	run("built-in private CIDR -> direct", func() { _ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}}) }, "127.0.0.1", "direct")

	fmt.Println("== blacklist (beats allow) ==")
	run("blacklist domain", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"evil.tp"}})
		_ = mgr.SetBlacklist(blacklist.Rules{Domains: []string{"evil.tp"}})
	}, "evil.tp", "")
	run("blacklist keyword", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"track-me.tp"}})
		_ = mgr.SetBlacklist(blacklist.Rules{Keywords: []string{"track"}})
	}, "track-me.tp", "")
	run("blacklist regex", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"reblock.tp"}})
		_ = mgr.SetBlacklist(blacklist.Rules{Regexes: []string{`.*reblock\.tp`}})
	}, "reblock.tp", "")
	run("blacklist IP", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{IPs: []string{"203.0.113.7/32"}})
		_ = mgr.SetBlacklist(blacklist.Rules{IPs: []string{"203.0.113.7/32"}})
	}, "203.0.113.7", "")

	fmt.Println("== custom rules: actions ==")
	run("custom direct", cr(rule("domain_suffix", "cdirect.tp", "direct", "")), "cdirect.tp", "direct")
	run("custom proxy (specific group)", cr(rule("domain_suffix", "cproxy.tp", "proxy", "g")), "cproxy.tp", "node")
	run("custom node target", cr(rule("domain_suffix", "cnode.tp", "node", "NODE")), "cnode.tp", "node")
	run("custom block (beats whitelist)", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"cblock.tp"}})
		_ = mgr.SetCustomRules(customrules.Rules{Rules: []apitypes.CustomRule{rule("domain_suffix", "cblock.tp", "block", "")}})
	}, "cblock.tp", "")

	fmt.Println("== custom rules: match kinds ==")
	run("custom match: keyword", cr(rule("keyword", "kw-host", "node", "NODE")), "kw-host.tp", "node")
	run("custom match: regex", cr(rule("regex", `.*rex\.tp`, "node", "NODE")), "rex.tp", "node")
	run("custom match: ip_cidr -> node", cr(rule("ip_cidr", "203.0.113.8/32", "node", "NODE")), "203.0.113.8", "node")

	fmt.Println("== custom rules: first-match ordering ==")
	// block before proxy on the same domain: the earlier rule wins.
	run("order: block then proxy -> block", cr(rule("domain_suffix", "ord.tp", "block", ""), rule("domain_suffix", "ord.tp", "proxy", "g")), "ord.tp", "")
	run("order: proxy then block -> node", cr(rule("domain_suffix", "ord.tp", "proxy", "g"), rule("domain_suffix", "ord.tp", "block", "")), "ord.tp", "node")

	fmt.Println("== process / device gates ==")
	run("process gate: listed process allowed", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}, Processes: []string{selfProc}})
	}, "allow.tp", "node")
	run("process gate: unlisted process blocked", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}, Processes: []string{"no-such-proc"}})
	}, "allow.tp", "")
	run("device gate: known source allowed", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}, Devices: []string{"127.0.0.1/32"}})
	}, "allow.tp", "node")
	run("device gate: unknown source blocked", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}, Devices: []string{"10.0.0.0/8"}})
	}, "allow.tp", "")

	fmt.Println("== Global routing mode ==")
	reset()
	_ = mgr.SetBlacklist(blacklist.Rules{Domains: []string{"evilg.tp"}})
	setClashMode(clashPort, "Global")
	selectProxyGroup(clashPort, "g")
	time.Sleep(200 * time.Millisecond)
	check("Global: unlisted -> node", "node", get("deny2.tp"))
	check("Global: blacklist still blocked", "", get("evilg.tp"))
	setClashMode(clashPort, "Rule")

	fmt.Println("== proxy grouping (auto-country) ==")
	// Re-apply a country-named node so an auto-country group forms, and route via it.
	hkOB, _ := json.Marshal(map[string]any{"type": "http", "tag": "🇭🇰 HK", "server": "node-exit.tp", "server_port": nodePort})
	_ = mgr.SetProxyGroups(proxygroups.Config{AutoCountry: true})
	_ = mgr.Apply([]apitypes.Node{{Tag: "🇭🇰 HK", Protocol: "http", Server: "node-exit.tp", Port: nodePort, Outbound: hkOB}})
	_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}})
	selectProxyGroup(clashPort, "🇭🇰 HK")
	time.Sleep(250 * time.Millisecond)
	check("auto-country group routes via node", "node", get("allow.tp"))
	// restore the plain node + manual group for the mode tests.
	_ = mgr.SetProxyGroups(proxygroups.Config{Groups: []proxygroups.Group{{Name: "g", Type: "select", Filter: "manual", Nodes: []string{"NODE"}}}})
	_ = mgr.Apply([]apitypes.Node{{Tag: "NODE", Protocol: "http", Server: "node-exit.tp", Port: nodePort, Outbound: nodeOB}})

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
	fmt.Println("== loopback excluded from Auto ==")
	// Dead local SOCKS (like a stopped Cloudflare WARP) must not sit in Auto —
	// otherwise urltest latches onto it and every proxied site blackholes.
	deadOB, _ := json.Marshal(map[string]any{"type": "socks", "tag": "dead-local", "server": "127.0.0.1", "server_port": 1, "version": "5"})
	_ = mgr.SetProxyGroups(proxygroups.Config{}) // default Auto over members
	_ = mgr.Apply([]apitypes.Node{
		{Tag: "dead-local", Protocol: "socks", Server: "127.0.0.1", Port: 1, Outbound: deadOB},
		{Tag: "NODE", Protocol: "http", Server: "node-exit.tp", Port: nodePort, Outbound: nodeOB},
	})
	time.Sleep(300 * time.Millisecond)
	autoMembers, _ := proxyGroupMembers(clashPort, "Auto")
	localMembers, localOK := proxyGroupMembers(clashPort, "Local")
	if contains(autoMembers, "dead-local") {
		fail++
		fmt.Printf("  FAIL  Auto must not include dead-local, got %v\n", autoMembers)
	} else {
		pass++
		fmt.Println("  PASS  Auto excludes loopback node")
	}
	if !localOK || !contains(localMembers, "dead-local") {
		fail++
		fmt.Printf("  FAIL  Local group should hold dead-local, got ok=%v %v\n", localOK, localMembers)
	} else {
		pass++
		fmt.Println("  PASS  Local group holds loopback node")
	}
	_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}})
	selectProxyGroup(clashPort, "Auto")
	time.Sleep(200 * time.Millisecond)
	check("proxy via Auto still hits live node", "node", get("allow.tp"))
	// restore for TUN / later sections
	_ = mgr.SetProxyGroups(proxygroups.Config{Groups: []proxygroups.Group{{Name: "g", Type: "select", Filter: "manual", Nodes: []string{"NODE"}}}})
	_ = mgr.Apply([]apitypes.Node{{Tag: "NODE", Protocol: "http", Server: "node-exit.tp", Port: nodePort, Outbound: nodeOB}})

	fmt.Println("== tun mode ==")
	if os.Geteuid() != 0 {
		fmt.Println("  SKIP  tun mode (needs root)")
	} else {
		// Regression: dns type=local + hijack-dns used to feedback-loop under
		// TUN ("nothing works"). sanitizeTunDNS must rewrite local so SetMode
		// succeeds and the box stays up.
		if err := mgr.SetDNS(apitypes.DNSConfig{
			Servers: []apitypes.DNSServer{{Tag: "local", Type: "local"}},
			Final:   "local",
		}); err != nil {
			fail++
			fmt.Printf("  FAIL  set dns local: %v\n", err)
		} else if err := mgr.SetMode(gateway.ModeTUN); err != nil {
			fail++
			fmt.Printf("  FAIL  tun mode start with dns local: %v\n", err)
		} else {
			pass++
			fmt.Println("  PASS  tun mode: gateway built + started (dns local sanitized)")
			_ = mgr.SetMode(gateway.ModeManual)
		}
		_ = mgr.SetDNS(dns) // restore hosts resolver for any later live section
	}

	// Live section (opt-in): apply REAL node(s) and fetch REAL sites through them,
	// asserting real target data comes back — this is what catches "connection
	// shows live but the site never actually loads".
	if selftestSubFile != "" {
		lp, lf := liveTest(selftestSubFile)
		pass += lp
		fail += lf
	}

	fmt.Printf("\n%d passed, %d failed\n", pass, fail)
	if fail > 0 {
		return fmt.Errorf("selftest: %d scenario(s) failed", fail)
	}
	return nil
}

// liveTest applies the real node(s) from a clash-yaml file and fetches real
// sites through them, asserting actual target data (not just a connection or a
// status code): a 204 probe, the exit IP (which must differ from the direct
// IP — proving bytes really traversed the node), and real HTML content.
func liveTest(subFile string) (pass, fail int) {
	ck := func(name string, ok bool, detail string) {
		if ok {
			pass++
			fmt.Printf("  PASS  %-42s %s\n", name, detail)
		} else {
			fail++
			fmt.Printf("  FAIL  %-42s %s\n", name, detail)
		}
	}
	fmt.Println("== live: real data through a real node ==")

	body, err := os.ReadFile(subFile)
	if err != nil {
		ck("read sub-file", false, err.Error())
		return
	}
	nodes := subscription.Parse(body)
	ck("parse real node(s)", len(nodes) > 0, fmt.Sprintf("%d node(s)", len(nodes)))
	if len(nodes) == 0 {
		return
	}

	mixedPort, clashPort := freePort(), freePort()
	dir, _ := os.MkdirTemp("", "tp-live-")
	defer os.RemoveAll(dir)
	baseCfg := fmt.Sprintf(`{"log":{"level":"error"},"experimental":{"clash_api":{"external_controller":"127.0.0.1:%d","secret":""}},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"blocked"},{"type":"selector","tag":"proxy","outbounds":["direct"]}],"route":{"rules":[{"action":"sniff"},{"network":["tcp","udp"],"action":"route","outbound":"blocked"}],"final":"blocked"}}`, clashPort, mixedPort)
	cfgPath := filepath.Join(dir, "config.json")
	_ = os.WriteFile(cfgPath, []byte(baseCfg), 0o644)

	engine := detect.New(200)
	mgr := gateway.NewManager(cfgPath, dir, whitelist.Rules{Domains: []string{"example.com", "api.ipify.org", "www.gstatic.com", "ip-api.com"}}, engine, "")
	mgr.SetInitialNodes(nodes)
	// Auto (urltest over all nodes) so egress uses a HEALTHY node: a real sub can
	// mix live and dead nodes (e.g. a host-local Warp endpoint that isn't
	// reachable here); urltest's health check drops the dead ones and picks the
	// fastest that actually connects.
	mgr.SetInitialProxyGroups(proxygroups.Config{AutoCountry: true})
	if err := mgr.Start(); err != nil {
		ck("gateway start with real node", false, err.Error())
		return
	}
	defer mgr.Close()
	selectProxyGroup(clashPort, "Auto")
	time.Sleep(3 * time.Second) // let urltest health-check the members and settle

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	viaNode := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 25 * time.Second}
	direct := &http.Client{Timeout: 12 * time.Second}
	// text fetches a URL's body, retrying briefly to absorb urltest warm-up.
	text := func(c *http.Client, u string) string {
		for attempt := 0; attempt < 3; attempt++ {
			resp, err := c.Get(u)
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			return strings.TrimSpace(string(b))
		}
		return ""
	}
	status := func(c *http.Client, u string) int {
		resp, err := c.Get(u)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	// 1) a 204 connectivity probe through the node (real TLS + real response).
	ck("gstatic 204 probe via node", status(viaNode, "https://www.gstatic.com/generate_204") == 204, "")
	// 2) exit IP via node must be a valid IP AND differ from the direct IP —
	//    this proves real bytes came back FROM the node, not just a live socket.
	nodeIP := text(viaNode, "https://api.ipify.org")
	directIP := text(direct, "https://api.ipify.org")
	ck("exit IP via node is real + != direct", net.ParseIP(nodeIP) != nil && nodeIP != directIP, fmt.Sprintf("node=%q direct=%q", nodeIP, directIP))
	// 3) real website content through the node (the actual page bytes).
	page := text(viaNode, "https://example.com")
	ck("example.com real content via node", strings.Contains(page, "Example Domain"), fmt.Sprintf("%d bytes", len(page)))

	liveOverseas(nodes, mgr, clashPort, viaNode, text, &pass, &fail)
	return
}

// liveOverseas exercises the shared Overseas group with the REAL nodes: it
// reconfigures the exclusion to drop one country the nodes actually have, then
// verifies (a) the group materializes excluding that region's node(s), and
// (b) real data fetched through the group exits from an allowed region (geoip
// via ip-api.com), never the excluded one — the core geofence-failover promise.
func liveOverseas(nodes []apitypes.Node, mgr *gateway.Manager, clashPort int, viaNode *http.Client, text func(*http.Client, string) string, pass, fail *int) {
	ck := func(name string, ok bool, detail string) {
		if ok {
			*pass++
			fmt.Printf("  PASS  %-42s %s\n", name, detail)
		} else {
			*fail++
			fmt.Printf("  FAIL  %-42s %s\n", name, detail)
		}
	}
	fmt.Println("== live: Overseas group (geofenced failover) ==")

	// Pick a country the nodes actually have, such that excluding it still leaves
	// ≥1 node for the group. If none qualifies (all nodes share one country, or
	// none carries a country), the group can't materialize — skip honestly.
	var excluded string
	for _, n := range nodes {
		c := proxygroups.Country(n.Tag)
		if c == "" {
			continue
		}
		remaining := 0
		for _, m := range nodes {
			if proxygroups.Country(m.Tag) != c {
				remaining++
			}
		}
		if remaining > 0 {
			excluded = c
			break
		}
	}
	if excluded == "" {
		ck("overseas: needs ≥2 node countries (SKIP)", true, "not enough distinct countries in the sub")
		return
	}

	if err := mgr.SetProxyGroups(proxygroups.Config{AutoCountry: true, ExcludeCountries: []string{excluded}}); err != nil {
		ck("overseas: reconfigure gateway", false, err.Error())
		return
	}
	time.Sleep(time.Second)

	// Structural: the Overseas group is built and excludes the excluded region.
	members, ok := overseasMembers(clashPort)
	badMember := false
	for _, m := range members {
		if proxygroups.Country(m) == excluded {
			badMember = true
		}
	}
	ck("overseas: group built, excludes "+excluded, ok && !badMember, fmt.Sprintf("members=%v", members))

	// Real data: route via Overseas and confirm the exit region is NOT the
	// excluded one (proves failover stays within allowed regions).
	selectProxyGroup(clashPort, proxygroups.OverseasGroupTag)
	time.Sleep(3 * time.Second) // urltest health-check within the allowed set
	cc, exitIP := geoCountry(viaNode, text)
	ck("overseas: real data exits allowed region (not "+excluded+")", cc != "" && cc != excluded, fmt.Sprintf("exit=%s ip=%s", cc, exitIP))
}

// geoCountry fetches the exit IP's country code via ip-api.com through the given
// client (i.e. through whatever proxy group it points at).
func geoCountry(c *http.Client, text func(*http.Client, string) string) (cc, ip string) {
	var g struct {
		CountryCode string `json:"countryCode"`
		Query       string `json:"query"`
	}
	_ = json.Unmarshal([]byte(text(c, "http://ip-api.com/json/")), &g)
	return g.CountryCode, g.Query
}

// overseasMembers reads the Overseas group's member tags from the Clash API.
func overseasMembers(clashPort int) ([]string, bool) {
	return proxyGroupMembers(clashPort, proxygroups.OverseasGroupTag)
}

// proxyGroupMembers returns the member tags of a Clash proxy group.
func proxyGroupMembers(clashPort int, name string) ([]string, bool) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/proxies", clashPort))
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	var d struct {
		Proxies map[string]struct {
			All []string `json:"all"`
		} `json:"proxies"`
	}
	if json.NewDecoder(resp.Body).Decode(&d) != nil {
		return nil, false
	}
	p, ok := d.Proxies[name]
	return p.All, ok
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// setClashMode switches the live Clash routing mode (Rule/Global) via the API.
func setClashMode(clashPort int, mode string) {
	body, _ := json.Marshal(map[string]string{"mode": mode})
	req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("http://127.0.0.1:%d/configs", clashPort), strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
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
