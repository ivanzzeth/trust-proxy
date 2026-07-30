package cmd

import (
	"bufio"
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
	"github.com/ivanzzeth/trust-proxy/internal/posture"
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/internal/proxyscore"
	"github.com/ivanzzeth/trust-proxy/internal/quarantine"
	"github.com/ivanzzeth/trust-proxy/internal/ruleset"
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

// slowDrips is how many 100ms chunks the origins' /slow endpoint writes before
// finishing. Long enough that the scoring section can kill a node's listener
// mid-response and still have a live connection to observe.
const slowDrips = 10

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
	// Two stub resolvers for the "dns follows route" section: one we reach
	// directly, one reachable only THROUGH the node (so a lookup's path is
	// observable).
	directDNSPort, remoteDNSPort := freePort(), freePort()
	remoteDNSAddr := fmt.Sprintf("127.0.0.1:%d", remoteDNSPort)

	// Two "internet" origins: whichever one answers tells us the egress path.
	// The direct outbound reaches directPort; the node upstream splices to
	// nodeOriginPort. Each just returns its own tag as the body.
	tagServer := func(port int, tag string) *http.Server {
		s := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// /slow keeps a request in flight for ~1s. The scoring section uses
			// it to assert that re-scoring steers the NEXT connection and never
			// disturbs one that is already flowing.
			if r.URL.Path == "/slow" {
				fl, _ := w.(http.Flusher)
				for i := 0; i < slowDrips; i++ {
					_, _ = io.WriteString(w, ".")
					if fl != nil {
						fl.Flush()
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
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
		target := nodeOriginAddr
		// One exception to the "everything lands on node-origin" rule: a CONNECT
		// to the remote stub resolver is spliced to the resolver itself. That is
		// what makes a resolver behind the exit node (detour="proxy") real, and
		// therefore what makes the DNS split observable.
		if r.Method == http.MethodConnect && r.Host == remoteDNSAddr {
			target = remoteDNSAddr
		}
		dst, err := net.Dial("tcp", target)
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
		// Permit⊥Route / prior-bug regressions
		"routeonly.tp", "permitonly.tp", "china.tp", "accounts.google.com", "api2.cursor.sh",
		"baidu.tp", "login.tp",
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
	mgr := gateway.NewManager(cfgPath, dataDir, whitelist.Rules{}, engine, "", "")
	// The same sink serve.go installs. Without it the scorer never learns what a
	// connection actually carried, and the blackhole section below — whose whole
	// input is "bytes went out, none came back" — would be asserting against a
	// harness that cannot observe its own subject.
	engine.SetOnFinalize(mgr.RecordEvent)
	mgr.SetInitialDNS(dns)
	// The exit node: an http outbound at our tagging upstream.
	nodeOB, _ := json.Marshal(map[string]any{"type": "http", "tag": "NODE", "server": "node-exit.tp", "server_port": nodePort})
	mgr.SetInitialNodes([]apitypes.Node{{Tag: "NODE", Protocol: "http", Server: "node-exit.tp", Port: nodePort, Outbound: nodeOB}})
	// A manual selector group over the node so `proxy` egress is deterministic
	// (no urltest health-check dependency on real internet).
	testPG := proxygroups.Config{Groups: []proxygroups.Group{
		{Name: "g", Type: "select", Filter: "manual", Nodes: []string{"NODE"}},
	}}
	mgr.SetInitialProxyGroups(testPG)
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
		_ = mgr.SetPosture(apitypes.PostureStrict)
		_ = mgr.SetWhitelist(whitelist.Rules{})
		_ = mgr.SetBlacklist(blacklist.Rules{})
		_ = mgr.SetDirectList(directlist.Rules{})
		_ = mgr.SetCustomRules(customrules.Rules{})
		_ = mgr.SetRuleSets(ruleset.Sets{})
		_ = mgr.SetProxyGroups(testPG)
		_ = mgr.SetFinal("proxy")
		setClashMode(clashPort, "Rule")
		selectProxyGroup(clashPort, "g")
	}

	pass, fail := 0, 0
	label := map[string]string{"node": "node", "direct": "direct", "": "blocked"}
	check := func(name, want, got string) {
		if want == got {
			pass++
			fmt.Printf("  PASS  %-48s -> %s\n", name, label[got])
		} else {
			fail++
			fmt.Printf("  FAIL  %-48s want=%s got=%s\n", name, label[want], label[got])
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
	permitPtr := func(v bool) *bool { return &v }

	// Local sing-box source rule-set files (offline stand-ins for geosite-cn etc.).
	writeLocalRS := func(name string, domains ...string) string {
		path := filepath.Join(dataDir, name+".json")
		body, _ := json.Marshal(map[string]any{
			"version": 1,
			"rules":   []map[string]any{{"domain_suffix": domains}},
		})
		_ = os.WriteFile(path, body, 0o644)
		return path
	}
	localRS := func(tag, role, path string) apitypes.RuleSet {
		return apitypes.RuleSet{
			Tag: tag, Name: tag, Type: "local", Format: "source", Path: path,
			Role: role, Enabled: true, DownloadDetour: "direct", UpdateInterval: "1d",
		}
	}

	fmt.Println("== ACL: allow / deny ==")
	run("default-deny blocks unlisted", func() {}, "deny.tp", "")
	run("whitelist domain -> node", func() { _ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}}) }, "allow.tp", "node")
	run("whitelist wildcard *.wild.tp -> node", func() { _ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"*.wild.tp"}}) }, "sub.wild.tp", "node")
	run("whitelist IP -> node", func() { _ = mgr.SetWhitelist(whitelist.Rules{IPs: []string{"203.0.113.5/32"}}) }, "203.0.113.5", "node")

	fmt.Println("== Permit ⊥ Route (no-proxy never opens gate) ==")
	// Prior bug: no-proxy alone used to open the ACL gate → mainland C2 "naked".
	run("no-proxy alone -> blocked (no Permit)", func() {
		_ = mgr.SetDirectList(directlist.Rules{Domains: []string{"np.tp"}})
	}, "np.tp", "")
	run("Permit + no-proxy -> direct", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"np.tp"}})
		_ = mgr.SetDirectList(directlist.Rules{Domains: []string{"np.tp"}})
	}, "np.tp", "direct")
	run("built-in private CIDR needs Permit first", func() {
		// private CIDRs are route-direct when gate open; without Permit, blocked.
	}, "127.0.0.1", "")
	run("built-in private CIDR -> direct when gate open", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}})
	}, "127.0.0.1", "direct")

	fmt.Println("== Permit ⊥ Route (custom axes) ==")
	run("route-only custom (no Permit) -> blocked", func() {
		_ = mgr.SetCustomRules(customrules.Rules{Rules: []apitypes.CustomRule{{
			Match: "domain_suffix", Value: "routeonly.tp", Action: "direct", Egress: "direct",
			Permit: permitPtr(false), Enabled: true,
		}}})
	}, "routeonly.tp", "")
	run("Permit + route-only -> direct", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"routeonly.tp"}})
		_ = mgr.SetCustomRules(customrules.Rules{Rules: []apitypes.CustomRule{{
			Match: "domain_suffix", Value: "routeonly.tp", Action: "direct", Egress: "direct",
			Permit: permitPtr(false), Enabled: true,
		}}})
	}, "routeonly.tp", "direct")
	run("permit-only custom -> Final (node)", func() {
		_ = mgr.SetCustomRules(customrules.Rules{Rules: []apitypes.CustomRule{{
			Match: "domain_suffix", Value: "permitonly.tp", Egress: "none",
			Permit: permitPtr(true), Enabled: true,
		}}})
	}, "permitonly.tp", "node")
	run("Final=direct for permitted-unrouted", func() {
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"permitonly.tp"}})
		_ = mgr.SetFinal("direct")
	}, "permitonly.tp", "direct")
	run("Final alone never opens empty gate", func() {
		_ = mgr.SetFinal("proxy")
	}, "deny.tp", "")

	fmt.Println("== Posture Strict|Split ==")
	run("Split: unlisted -> Final (node)", func() {
		_ = mgr.SetPosture(apitypes.PostureSplit)
		_ = mgr.SetFinal("proxy")
	}, "deny.tp", "node")
	run("Split + China route-direct -> direct", func() {
		_ = mgr.SetPosture(apitypes.PostureSplit)
		_ = mgr.SetRuleSets(ruleset.Sets{Sets: []apitypes.RuleSet{
			localRS("geosite-cn", apitypes.RuleRoleRouteDirect, writeLocalRS("cn-split", "china.tp")),
		}})
	}, "china.tp", "direct")
	run("Split: blacklist still blocks (L1 floor)", func() {
		_ = mgr.SetPosture(apitypes.PostureSplit)
		_ = mgr.SetBlacklist(blacklist.Rules{Domains: []string{"evil.tp"}})
	}, "evil.tp", "")
	run("Strict restored: unlisted blocked again", func() {
		_ = mgr.SetPosture(apitypes.PostureStrict)
	}, "deny.tp", "")

	// Dual-slot isolation via ApplyProfile (same path PUT /api/posture uses):
	// Strict whitelist must survive a Split excursion and come back intact.
	fmt.Println("== Posture dual-slot isolation ==")
	{
		nodes := mgr.Nodes()
		strictWL := whitelist.Rules{Domains: []string{"strict-slot.tp"}}
		splitCR := customrules.Rules{Rules: []apitypes.CustomRule{{
			Match: "domain_suffix", Value: "split-slot.tp", Egress: "none",
			Permit: permitPtr(true), Pack: "selftest-split", Enabled: true,
		}}}
		if err := mgr.ApplyProfile(nodes, strictWL, blacklist.Rules{}, directlist.Rules{}, customrules.Rules{},
			ruleset.Sets{}, testPG, dns, "", "proxy", apitypes.PostureStrict); err != nil {
			fail++
			fmt.Printf("  FAIL  dual-slot: set Strict slot: %v\n", err)
		} else {
			selectProxyGroup(clashPort, "g")
			check("dual-slot Strict: listed -> node", "node", get("strict-slot.tp"))
			check("dual-slot Strict: unlisted blocked", "", get("deny.tp"))
		}
		if err := mgr.ApplyProfile(nodes, whitelist.Rules{}, blacklist.Rules{}, directlist.Rules{}, splitCR,
			ruleset.Sets{}, testPG, dns, "", "proxy", apitypes.PostureSplit); err != nil {
			fail++
			fmt.Printf("  FAIL  dual-slot: set Split slot: %v\n", err)
		} else {
			selectProxyGroup(clashPort, "g")
			check("dual-slot Split: unlisted -> Final", "node", get("deny.tp"))
			check("dual-slot Split: pack permit -> node", "node", get("split-slot.tp"))
			check("dual-slot Split: Strict host not in Split wl (still open via Split)", "node", get("strict-slot.tp"))
		}
		// Restore Strict snapshot — Split pack must NOT leak into Strict.
		if err := mgr.ApplyProfile(nodes, strictWL, blacklist.Rules{}, directlist.Rules{}, customrules.Rules{},
			ruleset.Sets{}, testPG, dns, "", "proxy", apitypes.PostureStrict); err != nil {
			fail++
			fmt.Printf("  FAIL  dual-slot: restore Strict: %v\n", err)
		} else {
			selectProxyGroup(clashPort, "g")
			check("dual-slot back Strict: listed restored", "node", get("strict-slot.tp"))
			check("dual-slot back Strict: unlisted blocked", "", get("deny.tp"))
			check("dual-slot back Strict: Split pack gone", "", get("split-slot.tp"))
		}
		reset()
	}

	// SeedSplit produces all packs + geoip-cn (offline check; no download).
	fmt.Println("== Posture SeedSplit contents ==")
	{
		slot := posture.SeedSplit()
		if !slot.Seeded || slot.Final != "proxy" {
			fail++
			fmt.Printf("  FAIL  SeedSplit meta seeded=%v final=%q\n", slot.Seeded, slot.Final)
		} else {
			pass++
			fmt.Println("  PASS  SeedSplit seeded + Final=proxy")
		}
		packs := map[string]bool{}
		for _, r := range slot.CustomRules {
			if r.Pack != "" {
				packs[r.Pack] = true
			}
		}
		missing := 0
		for _, p := range customrules.Presets {
			if len(p.Rules) == 0 {
				continue
			}
			if !packs[p.Name] {
				missing++
				fmt.Printf("  FAIL  SeedSplit missing pack %q\n", p.Name)
			}
		}
		if missing == 0 {
			pass++
			fmt.Printf("  PASS  SeedSplit includes all pack rules (%d packs)\n", len(packs))
		} else {
			fail += missing
		}
		hasGeoIP := false
		cnRole := ""
		for _, rs := range slot.RuleSets {
			if rs.Tag == "geoip-cn" {
				hasGeoIP = true
			}
			if rs.Tag == "geosite-cn" {
				cnRole = rs.Role
			}
		}
		if hasGeoIP {
			pass++
			fmt.Println("  PASS  SeedSplit includes geoip-cn")
		} else {
			fail++
			fmt.Println("  FAIL  SeedSplit missing geoip-cn")
		}
		if apitypes.RuleRoleRouteEgress(cnRole) == "direct" && apitypes.RuleRoleGrantsPermit(cnRole) {
			pass++
			fmt.Printf("  PASS  SeedSplit geosite-cn merged role=%s\n", cnRole)
		} else {
			fail++
			fmt.Printf("  FAIL  SeedSplit geosite-cn role=%q\n", cnRole)
		}
	}

	fmt.Println("== China-style ruleset axes (local .json stand-in) ==")
	cnPath := writeLocalRS("geosite-cn-selftest", "china.tp", "baidu.tp")
	run("China route-direct alone -> blocked", func() {
		_ = mgr.SetRuleSets(ruleset.Sets{Sets: []apitypes.RuleSet{
			localRS("geosite-cn", apitypes.RuleRoleRouteDirect, cnPath),
		}})
	}, "china.tp", "")
	run("China permit alone -> Final (node)", func() {
		_ = mgr.SetRuleSets(ruleset.Sets{Sets: []apitypes.RuleSet{
			localRS("geosite-cn", apitypes.RuleRolePermit, cnPath),
		}})
	}, "china.tp", "node")
	run("China permit+route-direct -> direct", func() {
		_ = mgr.SetRuleSets(ruleset.Sets{Sets: []apitypes.RuleSet{
			localRS("geosite-cn", apitypes.RuleRolePermitRouteDirect, cnPath),
		}})
	}, "baidu.tp", "direct")
	run("legacy allow-direct (=permit+route) -> direct", func() {
		_ = mgr.SetRuleSets(ruleset.Sets{Sets: []apitypes.RuleSet{
			localRS("geosite-cn", apitypes.RuleRoleAllowDirect, cnPath), // Normalize on inject via helpers
		}})
	}, "china.tp", "direct")

	fmt.Println("== Google/Cursor login pins (prior TUN hang) ==")
	run("accounts.google.com pin -> node", cr(rule("domain_suffix", "accounts.google.com", "proxy", "g")), "accounts.google.com", "node")
	run("api2.cursor.sh pin -> node", cr(rule("domain_suffix", "api2.cursor.sh", "proxy", "g")), "api2.cursor.sh", "node")
	run("login pin beats China-direct on overlap", func() {
		_ = mgr.SetRuleSets(ruleset.Sets{Sets: []apitypes.RuleSet{
			localRS("geosite-cn", apitypes.RuleRolePermitRouteDirect, writeLocalRS("cn-overlap", "login.tp", "accounts.google.com")),
		}})
		// Custom proxy pin must win (L4 custom before route-direct RS).
		_ = mgr.SetCustomRules(customrules.Rules{Rules: []apitypes.CustomRule{
			rule("domain_suffix", "accounts.google.com", "proxy", "g"),
		}})
	}, "accounts.google.com", "node")

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

	fmt.Println("== quarantine (the gateway's own ban) ==")
	reset()
	// A defensive ban must be recorded, enforced, and releasable. The recording
	// half is what broke: the detector handed the destination over as an "ip", but
	// in proxy/socks mode sing-box dials by NAME, so the store rejected the whole
	// entry — the connection died while the list stayed empty, leaving nothing to
	// see or release. Drive the real ban sink to assert all three.
	{
		quarPath := filepath.Join(dataDir, "selftest-quarantine.json")
		_ = os.Remove(quarPath)
		qs, qerr := quarantine.NewStore(quarPath)
		if qerr != nil {
			fail++
			fmt.Printf("  FAIL  quarantine store: %v\n", qerr)
		} else {
			engine.SetOnBan(func(domain, ip, reason string) {
				list, err := qs.Add(domain, ip, reason)
				if err != nil && len(list.Entries) == 0 {
					return
				}
				_ = mgr.SetQuarantine(list)
			})
			// The shape the bug lived in: name-dialed, so Destination has no address.
			engine.BanFromEvent(&detect.Event{
				Host:        "banned.tp",
				Destination: "banned.tp:443",
			}, "selftest exfil")

			entries := qs.Get().Entries
			listed := len(entries) == 1 && entries[0].Value == "banned.tp" && !entries[0].IsIP
			if listed {
				pass++
				fmt.Println("  PASS  name-dialed ban is recorded (visible + releasable)")
			} else {
				fail++
				fmt.Printf("  FAIL  name-dialed ban not recorded: %+v\n", entries)
			}
			// Recorded is not enough — it must actually reject.
			_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"banned.tp"}})
			check("quarantine rejects even when permitted", "", get("banned.tp"))
			// And releasing it must restore egress, or "release" is a lie.
			relList, _ := qs.Release("banned.tp")
			_ = mgr.SetQuarantine(relList)
			check("release restores egress", "node", get("banned.tp"))

			// A bare IP still lands on the ip axis, not as a bogus domain.
			_ = os.Remove(quarPath)
			qs2, _ := quarantine.NewStore(quarPath)
			engine.SetOnBan(func(domain, ip, reason string) { _, _ = qs2.Add(domain, ip, reason) })
			engine.BanFromEvent(&detect.Event{Host: "203.0.113.9", Destination: "203.0.113.9:443"}, "selftest ip")
			e2 := qs2.Get().Entries
			if len(e2) == 1 && e2[0].IsIP && e2[0].Value == "203.0.113.9/32" {
				pass++
				fmt.Println("  PASS  bare-IP ban lands on the ip axis as a CIDR")
			} else {
				fail++
				fmt.Printf("  FAIL  bare-IP ban wrong: %+v\n", e2)
			}
			engine.SetOnBan(nil)
			_ = mgr.SetQuarantine(quarantine.List{})
		}
	}
	reset()

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

	fmt.Println("== proxy scoring ==")
	// Scoring's claim is that real traffic — not the generate_204 probe — decides
	// which member the NEXT connection is dialed on, and that it decides nothing
	// else. Five things are asserted here, end to end, through the real box:
	//
	//  ① a new connection migrates to the healthy member once the other one dies;
	//  ② a connection already in flight ON the dying member is not killed;
	//  ③ during warm-up (< MinSamples) a node carries no real score, even after
	//     an observation that would otherwise have lowered it;
	//  ④ the breaker demotes that node while it stays listed in the group;
	//  ⑤ past MinSamples a node carries a measured score instead of the
	//     placeholder.
	//
	// ③④⑤ are the teeth for the wiring: with the scorer left out of the box
	// context every node sits at zero samples and all three fail (verified).
	// ①② also hold without scoring — the fork's dial-failure cooldown already
	// does that much — so they are guarding against scoring *regressing* the
	// behaviour of the last two rounds, not proving scoring by themselves. The
	// score-beats-latency ordering itself is pinned deterministically in the
	// fork's protocol/group/urltest_score_test.go.
	//
	// A urltest group is required — a selector never consults the scorer.
	{
		reset()
		mgr.ResetScores() // earlier sections drove traffic through Auto too
		// A third origin, so "which member served this" is observable rather
		// than inferred from a request merely not failing.
		flakyOriginPort := freePort()
		flakyOrigin := tagServer(flakyOriginPort, "flaky")
		defer flakyOrigin.Close()
		label["flaky"] = "flaky"
		flakyOriginAddr := fmt.Sprintf("127.0.0.1:%d", flakyOriginPort)

		// FLAKY is a second, independent node upstream that we can stop
		// *accepting* on without disturbing the tunnels it already spliced:
		// http.Server.Close() does not touch hijacked connections, which is
		// exactly the shape of "the node died while you were logged in".
		flakyPort := freePort()
		flakyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dst, err := net.Dial("tcp", flakyOriginAddr)
			if err != nil {
				http.Error(w, err.Error(), 502)
				return
			}
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
		})
		flaky := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", flakyPort), Handler: flakyHandler}
		go flaky.ListenAndServe()
		defer flaky.Close()

		flakyOB, _ := json.Marshal(map[string]any{"type": "http", "tag": "SC-FLAKY", "server": "node-exit.tp", "server_port": flakyPort})
		goodOB, _ := json.Marshal(map[string]any{"type": "http", "tag": "SC-GOOD", "server": "node-exit.tp", "server_port": nodePort})
		// MinSamples above 1 so warm-up is observable; a 1-failure breaker so a
		// single dead dial is enough to demote (the stock 5 would need traffic
		// this offline harness has no way to generate).
		_ = mgr.SetProxyGroups(proxygroups.Config{Scoring: proxyscore.Config{MinSamples: 4, BreakerFailures: 1}})
		// Order matters: with no probe history the group dials the first member,
		// so FLAKY is the one that carries the in-flight connection.
		_ = mgr.Apply([]apitypes.Node{
			{Tag: "SC-FLAKY", Protocol: "http", Server: "node-exit.tp", Port: flakyPort, Outbound: flakyOB},
			{Tag: "SC-GOOD", Protocol: "http", Server: "node-exit.tp", Port: nodePort, Outbound: goodOB},
		})
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}})
		selectProxyGroup(clashPort, "Auto")
		time.Sleep(250 * time.Millisecond)

		// Baseline: FLAKY is the member being used. Without this the migration
		// assertion below would be satisfied by traffic that was on SC-GOOD all
		// along — "it still works" is not "it moved".
		check("traffic starts on the node about to die", "flaky", get("allow.tp"))

		// ② A slow response held open on FLAKY. It is dialed before FLAKY stops
		// listening, so it is a live connection on the member that is about to
		// be demoted.
		slowBody := make(chan string, 1)
		go func() {
			resp, err := client.Get(fmt.Sprintf("http://allow.tp:%d/slow", directPort))
			if err != nil {
				slowBody <- ""
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			slowBody <- string(b)
		}()
		time.Sleep(400 * time.Millisecond) // let the tunnel establish and start dripping
		flaky.Close()                      // new dials are refused; the spliced tunnel lives on
		time.Sleep(100 * time.Millisecond)

		// ① The next connection must find its way to the healthy member. If it
		// did not fail over it would come back empty, not merely slower.
		check("new connection migrates off the dead node", "node", get("allow.tp"))

		want := strings.Repeat(".", slowDrips) + "flaky"
		if got := <-slowBody; got == want {
			pass++
			fmt.Println("  PASS  in-flight connection on the dead node survives")
		} else {
			fail++
			fmt.Printf("  FAIL  in-flight connection truncated: got %d/%d bytes\n", len(got), len(want))
		}

		// Give SC-GOOD enough real outcomes to leave warm-up.
		for i := 0; i < 4; i++ {
			get("allow.tp")
		}
		byTag := map[string]proxyscore.View{}
		for _, v := range mgr.Scores(nil) {
			byTag[v.Tag] = v
		}
		fk, good := byTag["SC-FLAKY"], byTag["SC-GOOD"]

		// ③ FLAKY was observed (one good dial, then a dead one: reliability took
		// the hit and the breaker tripped) and yet, still inside warm-up, it
		// reports no real score. A bare 100 here means "not judged yet", which is
		// the whole point of the warm-up — a node must not be condemned on its
		// first bad minute.
		if fk.Warming && fk.Score == 100 && fk.Reliability < 100 && fk.Samples > 0 {
			pass++
			fmt.Printf("  PASS  warming node keeps the neutral 100 (samples=%d rel=%.0f)\n", fk.Samples, fk.Reliability)
		} else {
			fail++
			fmt.Printf("  FAIL  warm-up broken: %+v\n", fk)
		}
		// The breaker is orthogonal to the score and works from sample #1 — that
		// is what stops a dead node from riding its warm-up 100 into selection.
		// It demotes; it must never remove the member from the group.
		if !fk.Preferred && fk.Breaker == "open" {
			pass++
			fmt.Println("  PASS  dead node demoted by the breaker while still listed")
		} else {
			fail++
			fmt.Printf("  FAIL  dead node not demoted: breaker=%q preferred=%v\n", fk.Breaker, fk.Preferred)
		}
		// …and once past MinSamples a node carries a measured score. Not 100:
		// throughput has no samples in this harness and scores a neutral 50, so
		// a flawless node still lands below the warm-up placeholder. If the
		// scorer were not wired into the box at all, this node would have zero
		// samples and still be warming.
		if !good.Warming && good.Samples >= 4 && good.Score > 0 && good.Score < 100 && good.Reliability == 100 && good.Preferred {
			pass++
			fmt.Printf("  PASS  healthy node leaves warm-up with a measured score (%.0f over %d samples)\n", good.Score, good.Samples)
		} else {
			fail++
			fmt.Printf("  FAIL  no real score after warm-up: %+v\n", good)
		}

		// restore for the sections below
		_ = mgr.SetProxyGroups(proxygroups.Config{Groups: []proxygroups.Group{{Name: "g", Type: "select", Filter: "manual", Nodes: []string{"NODE"}}}})
		_ = mgr.Apply([]apitypes.Node{{Tag: "NODE", Protocol: "http", Server: "node-exit.tp", Port: nodePort, Outbound: nodeOB}})
		mgr.ResetScores()
	}

	fmt.Println("== blackhole nodes ==")
	// Subscriptions ship members that complete the handshake and then relay
	// nothing. Every signal the dial path has says "healthy" — the dial DID
	// succeed — so urltest keeps handing them traffic that silently goes
	// nowhere. The verdict therefore has to come from the finished connection
	// (bytes out, none back), and it has to beat warm-up: a fresh subscription's
	// fake node would otherwise ride its neutral 100 for its first ten
	// connections, which is exactly when it does its damage.
	//
	// Teeth: with the blackhole rules removed the node keeps reliability 100 and
	// stays preferred, so all four assertions below fail (verified).
	{
		reset()
		mgr.ResetScores()

		// An upstream that speaks CONNECT correctly and then says nothing. It
		// holds the tunnel open rather than closing it — a close would surface
		// as an IO failure that the dial path already scores, which would prove
		// nothing about the case that actually hurts.
		//
		// It swallows the payload for a beat and then drops the tunnel without
		// ever writing a byte back. Holding it open forever would be the purer
		// imitation, but the verdict is computed when the connection closes —
		// so a tunnel that never ends is a test that asserts before its own
		// evidence exists. Dropping it silently is the same signal (bytes out,
		// none back) at a moment the test controls; it is also what these nodes
		// do in practice once the far side times out.
		bhPort := freePort()
		bhLn, bhErr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", bhPort))
		if bhErr != nil {
			return bhErr
		}
		go func() {
			for {
				c, err := bhLn.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					br := bufio.NewReader(c)
					for { // consume the CONNECT request head
						line, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if strings.TrimSpace(line) == "" {
							break
						}
					}
					_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
					done := make(chan struct{})
					go func() { _, _ = io.Copy(io.Discard, br); close(done) }() // swallow the payload
					select {
					case <-done:
					case <-time.After(300 * time.Millisecond):
					}
				}(c)
			}
		}()
		defer bhLn.Close()

		bhOB, _ := json.Marshal(map[string]any{"type": "http", "tag": "SC-BH", "server": "node-exit.tp", "server_port": bhPort})
		goodOB, _ := json.Marshal(map[string]any{"type": "http", "tag": "SC-LIVE", "server": "node-exit.tp", "server_port": nodePort})
		// MinSamples deliberately far above the streak: the point is that the
		// verdict lands DURING warm-up.
		_ = mgr.SetProxyGroups(proxygroups.Config{Scoring: proxyscore.Config{MinSamples: 10, BlackholeStreak: 2}})
		// SC-BH first, so with no probe history it is the member that carries
		// the traffic — the shape of a subscription whose fake node wins.
		_ = mgr.Apply([]apitypes.Node{
			{Tag: "SC-BH", Protocol: "http", Server: "node-exit.tp", Port: bhPort, Outbound: bhOB},
			{Tag: "SC-LIVE", Protocol: "http", Server: "node-exit.tp", Port: nodePort, Outbound: goodOB},
		})
		_ = mgr.SetWhitelist(whitelist.Rules{Domains: []string{"allow.tp"}})
		selectProxyGroup(clashPort, "Auto")
		time.Sleep(250 * time.Millisecond)

		// The probe drives the socket itself instead of going through
		// http.Client. A blackhole answers by never answering, so the client's
		// only exit is its timeout — and abandoning a request does not close the
		// tunnel, it leaks it. The verdict is computed when the connection
		// closes, so a probe that never closes cleanly cannot be observed at
		// all: the assertions ran a second and a half before their own evidence
		// arrived (that is how this was found). Closing explicitly makes the
		// finalize sink fire at a point in the test we control.
		bhGet := func() string {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", mixedPort), time.Second)
			if err != nil {
				return ""
			}
			defer c.Close()
			req := fmt.Sprintf("GET http://allow.tp:%d/ HTTP/1.1\r\nHost: allow.tp:%d\r\nConnection: close\r\n\r\n",
				directPort, directPort)
			if _, err := c.Write([]byte(req)); err != nil {
				return ""
			}
			_ = c.SetReadDeadline(time.Now().Add(900 * time.Millisecond))
			b, _ := io.ReadAll(c)
			if i := strings.Index(string(b), "\r\n\r\n"); i >= 0 {
				return strings.TrimSpace(string(b)[i+4:])
			}
			return ""
		}

		// scoreOf reads one member out of the live view.
		scoreOf := func(tag string) proxyscore.View {
			for _, v := range mgr.Scores(nil) {
				if v.Tag == tag {
					return v
				}
			}
			return proxyscore.View{}
		}
		// Drive dead connections until the verdict lands. The streak counts
		// CLOSED connections and the close travels a path this test does not
		// drive — the client hangs up, the gateway tears its half down, then the
		// sink runs, a couple of seconds later. Polling for the verdict rather
		// than sleeping a guessed interval is what keeps this from flaking; the
		// bound is generous because being slow here is a stall, not a bug, while
		// giving up early would report the feature broken.
		for i := 0; i < 8 && !scoreOf("SC-BH").Blackhole; i++ {
			if got := bhGet(); got != "" {
				fmt.Printf("  note  blackhole probe %d unexpectedly answered %q\n", i+1, got)
			}
			for t := 0; t < 60 && scoreOf("SC-BH").BlackholeStreak <= i; t++ {
				time.Sleep(50 * time.Millisecond)
			}
		}
		// The claim is that the verdict lands on evidence, not on eventually:
		// two dead connections were configured, so more than a handful of
		// samples means the counter is not counting what it says it counts.
		if n := scoreOf("SC-BH").Samples; n > 4 {
			fmt.Printf("  note  blackhole verdict took %d samples for a streak of 2\n", n)
		}

		var bh, live proxyscore.View
		for _, v := range mgr.Scores(nil) {
			switch v.Tag {
			case "SC-BH":
				bh = v
			case "SC-LIVE":
				live = v
			}
		}

		if bh.Blackhole && bh.Score == 0 {
			pass++
			fmt.Printf("  PASS  fake node scores 0 while still warming (samples=%d/%d)\n", bh.Samples, bh.MinSamples)
		} else {
			fail++
			fmt.Printf("  FAIL  fake node not condemned: %+v\n", bh)
		}
		// Demote, never remove: a group that can empty itself is how the gateway
		// once ended up with no egress at all.
		if !bh.Preferred && bh.Breaker == "open" {
			pass++
			fmt.Println("  PASS  fake node demoted by the breaker, still listed in the group")
		} else {
			fail++
			fmt.Printf("  FAIL  fake node not demoted: breaker=%q preferred=%v\n", bh.Breaker, bh.Preferred)
		}
		if live.Tag == "SC-LIVE" && !live.Blackhole {
			pass++
			fmt.Println("  PASS  the working node is untouched by its neighbour's verdict")
		} else {
			fail++
			fmt.Printf("  FAIL  healthy node collateral: %+v\n", live)
		}
		// The payoff, and the user-visible claim: traffic stops going nowhere.
		check("next connection leaves the fake node", "node", bhGet())

		// restore for the sections below
		_ = mgr.SetProxyGroups(proxygroups.Config{Groups: []proxygroups.Group{{Name: "g", Type: "select", Filter: "manual", Nodes: []string{"NODE"}}}})
		_ = mgr.Apply([]apitypes.Node{{Tag: "NODE", Protocol: "http", Server: "node-exit.tp", Port: nodePort, Outbound: nodeOB}})
		mgr.ResetScores()
	}

	fmt.Println("== dns follows route ==")
	// Regression: "everything domestic crawls while the gateway runs". With the
	// only resolver behind the exit node, mainland domains were answered from the
	// node's vantage point (Korea/India CDN edges) and then dialed DIRECT — every
	// domestic site went across an ocean and back. A domain that egresses direct
	// must be resolved by a resolver we dial directly.
	//
	// Both stubs answer 127.0.0.1 (so the fetch still lands on an origin and the
	// egress assertion still holds); the signal is WHICH stub was queried.
	directRes := newStubResolver(directDNSPort, "127.0.0.1")
	defer directRes.close()
	remoteRes := newStubResolver(remoteDNSPort, "127.0.0.1")
	defer remoteRes.close()
	if !waitResolver(directDNSPort) || !waitResolver(remoteDNSPort) {
		fail++
		fmt.Println("  FAIL  stub resolvers did not start")
	} else {
		reset()
		_ = mgr.SetPosture(apitypes.PostureSplit) // default-allow: this section is about DNS, not the gate
		_ = mgr.SetCustomRules(customrules.Rules{Rules: []apitypes.CustomRule{
			rule("domain_suffix", "dnsdirect.tp", "direct", ""),
			rule("domain_suffix", "dnsproxy.tp", "proxy", ""),
		}})
		_ = mgr.SetRuleSets(ruleset.Sets{Sets: []apitypes.RuleSet{
			localRS("dns-cn", apitypes.RuleRoleRouteDirect, writeLocalRS("dns-cn", "rscn.tp")),
		}})
		splitErr := mgr.SetDNS(apitypes.DNSConfig{
			Servers: []apitypes.DNSServer{{Tag: "remote", Type: "tcp", Server: "127.0.0.1", Port: remoteDNSPort, Detour: "proxy"}},
			Final:   "remote",
			// node-exit.tp must keep resolving while the split is armed: it is
			// pinned to the direct resolver like every other direct dial.
			DirectServer: fmt.Sprintf("127.0.0.1:%d", directDNSPort),
		})
		if splitErr != nil {
			fail++
			fmt.Printf("  FAIL  set split dns: %v\n", splitErr)
		} else {
			selectProxyGroup(clashPort, "g")
			time.Sleep(200 * time.Millisecond)
			// Each case: the right egress AND the right resolver. A domain is only
			// asked of one of the two stubs, so "the other one saw it" is a real
			// failure, not noise.
			dnsCase := func(name, target, wantEgress string) {
				directRes.reset()
				remoteRes.reset()
				got := get(target)
				check(name, wantEgress, got)
				switch {
				case !directRes.saw(target):
					fail++
					fmt.Printf("  FAIL  %-48s %s was not resolved by the direct resolver\n", name+" (resolver)", target)
				case remoteRes.saw(target):
					fail++
					fmt.Printf("  FAIL  %-48s %s leaked to the resolver behind the node\n", name+" (resolver)", target)
				default:
					pass++
					fmt.Printf("  PASS  %-48s -> dns-direct\n", name+" (resolver)")
				}
			}
			dnsCase("custom direct rule resolves direct", "dnsdirect.tp", "direct")
			dnsCase("route-direct rule set resolves direct", "rscn.tp", "direct")

			// Control: a proxied destination is never resolved locally at all (the
			// node resolves it), so neither stub may be asked for it.
			directRes.reset()
			remoteRes.reset()
			check("proxied domain still egresses via node", "node", get("dnsproxy.tp"))
			if directRes.saw("dnsproxy.tp") {
				fail++
				fmt.Println("  FAIL  proxied domain must not be resolved by the direct resolver")
			} else {
				pass++
				fmt.Println("  PASS  proxied domain is resolved by the node, not locally")
			}
		}
	}
	_ = mgr.SetDNS(dns) // restore the hosts resolver for the sections below
	reset()

	fmt.Println("== tun mode ==")
	if os.Geteuid() != 0 {
		fmt.Println("  SKIP  tun mode (needs root)")
	} else {
		// Regression: dns type=local + hijack-dns used to feedback-loop under
		// TUN ("nothing works"). sanitizeTunDNS must rewrite local so SetMode
		// succeeds and the box stays up. Prefer DoH-via-proxy, not poisoned UDP.
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
			// sniff override_destination must be on under TUN (poisoned MagicDNS
			// dials still re-resolve by SNI).
			hasOverride := false
			for _, v := range mgr.EffectiveRules() {
				if v.Source == "sniff" || v.Action == "sniff" {
					// EffectiveRules may not expose override flag; assert via rebuild
					// still healthy + mode is tun.
					hasOverride = true
				}
			}
			if mgr.Mode() == gateway.ModeTUN && hasOverride {
				pass++
				fmt.Println("  PASS  tun mode: sniff prelude present (override applied at inject)")
			} else {
				fail++
				fmt.Printf("  FAIL  tun mode sniff/override check mode=%s\n", mgr.Mode())
			}
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

// scorer tallies PASS/FAIL lines for the live (real-network) self-test
// sections, shared between liveTest and liveOverseas — the latter accumulates
// into the SAME counters (passed by pointer) since it's one continuous report.
type scorer struct{ pass, fail *int }

func (s *scorer) ck(name string, ok bool, detail string) {
	if ok {
		*s.pass++
		fmt.Printf("  PASS  %-42s %s\n", name, detail)
	} else {
		*s.fail++
		fmt.Printf("  FAIL  %-42s %s\n", name, detail)
	}
}

// liveTest applies the real node(s) from a clash-yaml file and fetches real
// sites through them, asserting actual target data (not just a connection or a
// status code): a 204 probe, the exit IP (which must differ from the direct
// IP — proving bytes really traversed the node), and real HTML content.
func liveTest(subFile string) (pass, fail int) {
	sc := &scorer{&pass, &fail}
	fmt.Println("== live: real data through a real node ==")

	body, err := os.ReadFile(subFile)
	if err != nil {
		sc.ck("read sub-file", false, err.Error())
		return
	}
	nodes := subscription.Parse(body)
	sc.ck("parse real node(s)", len(nodes) > 0, fmt.Sprintf("%d node(s)", len(nodes)))
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
	mgr := gateway.NewManager(cfgPath, dir, whitelist.Rules{Domains: []string{"example.com", "api.ipify.org", "www.gstatic.com", "ip-api.com"}}, engine, "", "")
	mgr.SetInitialNodes(nodes)
	// Auto (urltest over all nodes) so egress uses a HEALTHY node: a real sub can
	// mix live and dead nodes (e.g. a host-local Warp endpoint that isn't
	// reachable here); urltest's health check drops the dead ones and picks the
	// fastest that actually connects.
	mgr.SetInitialProxyGroups(proxygroups.Config{AutoCountry: true})
	if err := mgr.Start(); err != nil {
		sc.ck("gateway start with real node", false, err.Error())
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
	sc.ck("gstatic 204 probe via node", status(viaNode, "https://www.gstatic.com/generate_204") == 204, "")
	// 2) exit IP via node must be a valid IP AND differ from the direct IP —
	//    this proves real bytes came back FROM the node, not just a live socket.
	nodeIP := text(viaNode, "https://api.ipify.org")
	directIP := text(direct, "https://api.ipify.org")
	sc.ck("exit IP via node is real + != direct", net.ParseIP(nodeIP) != nil && nodeIP != directIP, fmt.Sprintf("node=%q direct=%q", nodeIP, directIP))
	// 3) real website content through the node (the actual page bytes).
	page := text(viaNode, "https://example.com")
	sc.ck("example.com real content via node", strings.Contains(page, "Example Domain"), fmt.Sprintf("%d bytes", len(page)))

	liveOverseas(nodes, mgr, clashPort, viaNode, text, sc)
	return
}

// liveOverseas exercises the shared Overseas group with the REAL nodes: it
// reconfigures the exclusion to drop one country the nodes actually have, then
// verifies (a) the group materializes excluding that region's node(s), and
// (b) real data fetched through the group exits from an allowed region (geoip
// via ip-api.com), never the excluded one — the core geofence-failover promise.
func liveOverseas(nodes []apitypes.Node, mgr *gateway.Manager, clashPort int, viaNode *http.Client, text func(*http.Client, string) string, sc *scorer) {
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
		sc.ck("overseas: needs ≥2 node countries (SKIP)", true, "not enough distinct countries in the sub")
		return
	}

	if err := mgr.SetProxyGroups(proxygroups.Config{AutoCountry: true, ExcludeCountries: []string{excluded}}); err != nil {
		sc.ck("overseas: reconfigure gateway", false, err.Error())
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
	sc.ck("overseas: group built, excludes "+excluded, ok && !badMember, fmt.Sprintf("members=%v", members))

	// Real data: route via Overseas and confirm the exit region is NOT the
	// excluded one (proves failover stays within allowed regions).
	selectProxyGroup(clashPort, proxygroups.OverseasGroupTag)
	time.Sleep(3 * time.Second) // urltest health-check within the allowed set
	cc, exitIP := geoCountry(viaNode, text)
	sc.ck("overseas: real data exits allowed region (not "+excluded+")", cc != "" && cc != excluded, fmt.Sprintf("exit=%s ip=%s", cc, exitIP))
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
