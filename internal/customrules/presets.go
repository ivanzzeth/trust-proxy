package customrules

import (
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Presets are curated policy packs. Each pack declares Permit and/or Route
// explicitly — Route never opens the ACL gate by itself.
//
// Prefer RuleSets (geosite-*) for broad services. Keep custom Rules when egress
// must pin a group (a country group, for account-bound AI services) or when no
// clean geosite category exists.
//
// China is split:
//   - "China (wide)" — Permit geosite-cn (security warning: mainland C2 allowed)
//   - "China-direct" — Route geosite-cn → direct only (does not permit)
//
// Old one-click "CN works" = enable both.
var Presets = []apitypes.PackPreset{
	// The four AI packs pin ONE country group each instead of routing through the
	// shared Overseas urltest. Overseas ranks ~all non-HK/CN nodes by latency, so
	// on a real subscription it spans a dozen countries (measured on a live
	// gateway: 26 nodes / 14 countries, including TR, VN, PH, TH, MY) and from
	// mainland China those are frequently the *fastest* — which is exactly how a
	// single logged-in ChatGPT session ends up dialling from GB, KR, SG and VN
	// within one week (measured, same gateway). Anthropic/OpenAI treat that as a
	// hijacked account: re-auth loops, "unusual activity", or a region they
	// refuse outright. A stable exit beats a fast one for anything account-bound.
	//
	// Egress stays "proxy" with Node set (not egress "node"): if the user has no
	// node in that country the group does not exist, and a proxy rule self-heals
	// to the default proxy group. Egress "node" would be dropped instead — and a
	// dropped rule loses its Permit too, so the service would be default-DENIED
	// rather than merely routed elsewhere.
	{
		Name: "Claude",
		Description: "Anthropic Claude (web, API, Claude Code, Artifacts): permit + pin every request to " + usTag + ". " +
			"Includes hCaptcha (the claude.ai login challenge) and the keyword catch-alls that cover hosts not yet listed.",
		Warning: "The keyword rules (anthropic / claude) permit any hostname containing those words, " +
			"not just Anthropic's. That is deliberate belt-and-braces for a service that keeps adding hosts — " +
			"drop those two rules if you want suffix-exact permits only.",
		Exit: apitypes.PackExitPinned,
		Rules: concatRules(
			countryRules("Claude", "US",
				"anthropic.com",         // api / console / statsig / a-api / s-cdn / assets-proxy
				"claude.ai",             // app / downloads / assets
				"claude.com",            // platform / status
				"claudeusercontent.com", // Artifacts iframes (*.frame.claudeusercontent.com)
				// claude.ai's login challenge. Shared infra, so this pins other
				// sites' hCaptcha too — that is the trade for a login that works.
				"hcaptcha.com",
			),
			countryKeywords("Claude", "US", "anthropic", "claude"),
		),
	},
	{
		Name:        "OpenAI",
		Description: "OpenAI ChatGPT / API / Sora / Codex: permit + pin every request to " + jpTag + ".",
		Warning: "The keyword rules (openai / chatgpt) permit any hostname containing those words. " +
			"Drop them if you want suffix-exact permits only.",
		Exit: apitypes.PackExitPinned,
		Rules: concatRules(
			countryRules("OpenAI", "JP",
				"openai.com",         // api / auth / cdn / files / images / sentinel / help
				"chatgpt.com",        // app, plus ab. / ws. / learn. and the Codex backend
				"oaistatic.com",      // web assets (auth-cdn, persistent, help-center-cdn)
				"oaiusercontent.com", // uploads / generated files (sdmntpr*)
				"sora.com",
			),
			countryKeywords("OpenAI", "JP", "openai", "chatgpt"),
		),
	},
	{
		Name: "Cursor",
		Description: "Cursor editor + Agent/tools: permit official hosts, pinned to " + usTag + "; Agent streaming " +
			"(api5.*) goes direct for stability. Under TUN these must be permitted or the IDE agent hangs. " +
			"Re-apply the pack to refresh.",
		Exit: apitypes.PackExitMixed,
		// More-specific matchers first: domain_suffix api5.cursor.sh must beat
		// the broad cursor.sh rule (first match wins).
		Rules: concatRules(
			directRules("Cursor", "api5.cursor.sh"),
			countryRules("Cursor", "US",
				"cursor.com", "cursor.sh",
				"cursorapi.com", "cursor-cdn.com", "cursorvm.com",
				"todesktop.com",
				"anysphere-binaries.s3.us-east-1.amazonaws.com",
			),
		),
	},
	{
		Name:        "AI (other)",
		Description: "Gemini / Grok / Perplexity / Copilot / inference hosts: permit + pin to " + usTag + ".",
		Exit:        apitypes.PackExitPinned,
		Rules: countryRules("AI (other)", "US",
			"gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
			"notebooklm.google.com", "labs.google", "deepmind.com",
			"x.ai", "grok.com", "perplexity.ai",
			"mistral.ai", "cohere.com", "groq.com", "poe.com",
			"huggingface.co", "hf.co", "midjourney.com", "suno.com",
			"ollama.com",
			// Coding assistants other than Cursor (own pack).
			"githubcopilot.com", "codeium.com", "windsurf.com",
			// Inference / model hosts an app or agent dials directly.
			"openrouter.ai", "together.ai", "fireworks.ai", "replicate.com",
			"deepinfra.com", "novita.ai", "anyscale.com",
			// Media generation.
			"elevenlabs.io", "runwayml.com", "stability.ai", "civitai.com",
			"heygen.com", "luma-api.com", "pika.art",
			"character.ai"),
	},
	{
		Name:        "Dev",
		Description: "GitHub + Microsoft-dev via geosite (permit+proxy), plus Git SSH / registry pins.",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRSRole(apitypes.RuleRolePermitRouteProxy, "geosite-github", "geosite-microsoft-dev"),
		Rules: concatRules(
			proxyRules("Dev", "ssh.github.com", "github.com", "githubusercontent.com"),
			proxyCIDRs("Dev", githubGitCIDRs...),
			proxyRules("Dev", "code.visualstudio.com", "vscode.download.prss.microsoft.com"),
			proxyRules("Dev",
				"npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org",
				"pkg.go.dev", "proxy.golang.org", "sum.golang.org",
				"docker.io", "docker.com"),
			// OS package repos. Without these a `docker build` running
			// `apt-get install` falls through to Final=direct and pulls from
			// the origin CDN at ~50 KB/s (measured: 6.4 MB/s once proxied) —
			// a base-image layer that should take seconds takes half an hour.
			// Language registries alone are not enough: every Dockerfile hits
			// apt/apk before it ever hits pip or npm.
			proxyRules("Dev",
				"deb.debian.org", "security.debian.org",
				"archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com",
				"dl-cdn.alpinelinux.org"),
		),
	},
	{
		Name:        "Telegram",
		Description: "Telegram geosite (permit+proxy) plus official DC IP ranges.",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRSRole(apitypes.RuleRolePermitRouteProxy, "geosite-telegram"),
		Rules:       proxyCIDRs("Telegram", telegramCIDRs...),
	},
	{
		Name:        "Slack",
		Description: "Slack via geosite-slack (permit+proxy).",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRSRole(apitypes.RuleRolePermitRouteProxy, "geosite-slack"),
		Rules:       []apitypes.CustomRule{},
	},
	{
		Name:        "Notion",
		Description: "Notion via geosite-notion (permit+proxy).",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRSRole(apitypes.RuleRolePermitRouteProxy, "geosite-notion"),
		Rules:       []apitypes.CustomRule{},
	},
	{
		Name:        "X",
		Description: "X (Twitter) via geosite-twitter (permit+proxy).",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRSRole(apitypes.RuleRolePermitRouteProxy, "geosite-twitter"),
		Rules:       []apitypes.CustomRule{},
	},
	{
		Name:        "Streaming",
		Description: "Netflix + Spotify geosite (permit+proxy) plus Disney+/HBO/Twitch suffixes.",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRSRole(apitypes.RuleRolePermitRouteProxy, "geosite-netflix", "geosite-spotify"),
		Rules: proxyRules("Streaming",
			"disneyplus.com", "disney-plus.net",
			"hbomax.com", "max.com",
			"twitch.tv", "ttvnw.net"),
	},
	{
		Name:        "Google",
		Description: "Google + YouTube geosite (permit+proxy), plus pinned login hosts ahead of China-direct routes.",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRSRole(apitypes.RuleRolePermitRouteProxy, "geosite-google", "geosite-youtube"),
		Rules: proxyRules("Google",
			"accounts.google.com",
			"accounts.youtube.com",
			"ssl.gstatic.com",
			"accounts.gstatic.com",
		),
	},
	{
		Name: "Apple",
		Description: "Apple / iCloud: permit geosite-apple + route direct. " +
			"(Route alone would not open the gate — this pack grants both.)",
		Exit:     apitypes.PackExitDirect,
		RuleSets: catalogRSRole(apitypes.RuleRolePermitRouteDirect, "geosite-apple"),
		Rules:    []apitypes.CustomRule{},
	},
	{
		Name: "China (wide)",
		Description: "Permit all geosite-cn destinations (mainland coverage). " +
			"Does NOT pick an egress — pair with China-direct for 直连, or set Final=proxy if unmatched should go overseas.",
		Warning: "Security: this opens the ACL gate for the entire mainland geosite list. " +
			"A C2 host in China would be allowed out. Only enable if you accept that trade-off.",
		RuleSets: catalogRSRole(apitypes.RuleRolePermit, "geosite-cn"),
		Rules:    []apitypes.CustomRule{},
	},
	{
		Name: "China-direct",
		Description: "Route geosite-cn → direct only. Does NOT permit those destinations. " +
			"Enable China (wide) as well if you want mainland sites to leave the network.",
		Exit:     apitypes.PackExitDirect,
		RuleSets: catalogRSRole(apitypes.RuleRoleRouteDirect, "geosite-cn"),
		Rules:    []apitypes.CustomRule{},
	},
}

func catalogRSRole(role string, tags ...string) []apitypes.PackRuleSet {
	out := make([]apitypes.PackRuleSet, 0, len(tags))
	for _, t := range tags {
		out = append(out, apitypes.PackRuleSet{CatalogTag: t, Role: role})
	}
	return out
}

// telegramCIDRs are Telegram's published DC ranges
// (https://core.telegram.org/resources/cidr.txt).
var telegramCIDRs = []string{
	"91.108.56.0/22",
	"91.108.4.0/22",
	"91.108.8.0/22",
	"91.108.16.0/22",
	"91.108.12.0/22",
	"91.108.20.0/22",
	"149.154.160.0/20",
	"91.105.192.0/23",
	"185.76.151.0/24",
	"2001:b28:f23d::/48",
	"2001:b28:f23f::/48",
	"2001:67c:4e8::/48",
	"2001:b28:f23c::/48",
	"2a0a:f280::/32",
}

var githubGitCIDRs = []string{
	"192.30.252.0/22",
	"185.199.108.0/22",
	"140.82.112.0/20",
	"143.55.64.0/20",
	"2a0a:a440::/29",
	"2606:50c0::/32",
	"20.201.28.151/32", "20.201.28.152/32",
	"20.205.243.160/32", "20.205.243.166/32",
	"20.87.245.0/32", "20.87.245.4/32",
	"4.237.22.38/32", "4.237.22.40/32",
	"4.228.31.150/32", "4.228.31.145/32",
	"20.207.73.82/32", "20.207.73.83/32",
	"20.27.177.113/32", "20.27.177.118/32",
	"20.200.245.247/32", "20.200.245.248/32",
	"20.175.192.147/32", "20.175.192.146/32",
	"20.233.83.145/32", "20.233.83.149/32",
	"20.29.134.23/32", "20.29.134.19/32",
	"20.199.39.232/32", "20.199.39.227/32",
	"20.217.135.5/32", "20.217.135.4/32",
	"4.225.11.194/32", "4.225.11.200/32",
	"4.208.26.197/32", "4.208.26.198/32",
	"20.26.156.215/32", "20.26.156.214/32",
}

func packRulesMatch(pack, match, action, node string, values ...string) []apitypes.CustomRule {
	p := true
	out := make([]apitypes.CustomRule, 0, len(values))
	for _, v := range values {
		out = append(out, apitypes.CustomRule{
			Match:   match,
			Value:   v,
			Action:  action,
			Egress:  action,
			Permit:  &p,
			Node:    node,
			Pack:    pack,
			Enabled: true,
		})
	}
	return out
}

func packRules(pack, action, node string, domains ...string) []apitypes.CustomRule {
	return packRulesMatch(pack, apitypes.CustomMatchDomainSuffix, action, node, domains...)
}

func proxyCIDRs(pack string, cidrs ...string) []apitypes.CustomRule {
	p := true
	out := make([]apitypes.CustomRule, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, apitypes.CustomRule{
			Match:   apitypes.CustomMatchIPCIDR,
			Value:   c,
			Action:  apitypes.CustomActionProxy,
			Egress:  apitypes.CustomEgressProxy,
			Permit:  &p,
			Pack:    pack,
			Enabled: true,
		})
	}
	return out
}

func concatRules(parts ...[]apitypes.CustomRule) []apitypes.CustomRule {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]apitypes.CustomRule, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func proxyRules(pack string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionProxy, "", domains...)
}

// Country group tags as the gateway builds them when AutoCountry is on
// (proxygroups.CountryName => flag + ISO code). Named here so a preset reads as
// "pinned to US" rather than as an emoji literal.
var (
	usTag = proxygroups.CountryName("US")
	jpTag = proxygroups.CountryName("JP")
)

// countryRules pins domains to one country group. See the comment above the AI
// presets for why the egress is "proxy"-with-Node and not "node".
func countryRules(pack, code string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionProxy, proxygroups.CountryName(code), domains...)
}

// countryKeywords is countryRules over domain_keyword matchers — the catch-all
// half of an AI pack, for the hosts a service adds between our releases.
func countryKeywords(pack, code string, keywords ...string) []apitypes.CustomRule {
	return packRulesMatch(pack, apitypes.CustomMatchKeyword, apitypes.CustomActionProxy, proxygroups.CountryName(code), keywords...)
}

func directRules(pack string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionDirect, "", domains...)
}
