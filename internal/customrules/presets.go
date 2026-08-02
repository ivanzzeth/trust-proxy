package customrules

import (
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Presets are curated policy packs. Each pack declares Permit and/or Route
// explicitly — Route never opens the ACL gate by itself.
//
// Prefer RuleSets (geosite-*) for broad services. Keep custom Rules when egress
// must pin a group (Overseas) or when no clean geosite category exists.
//
// China is split:
//   - "China (wide)" — Permit geosite-cn (security warning: mainland C2 allowed)
//   - "China-direct" — Route geosite-cn → direct only (does not permit)
//
// Old one-click "CN works" = enable both.
var Presets = []apitypes.PackPreset{
	{
		Name:        "Claude",
		Description: "Anthropic Claude (web, API, Claude Code): permit domains + route via Overseas (never HK/CN).",
		Exit:        apitypes.PackExitOverseas,
		Rules:       overseasRules("Claude", "anthropic.com", "claude.ai", "claude.com"),
	},
	{
		Name:        "OpenAI",
		Description: "OpenAI ChatGPT / API / Sora: permit domains + route via Overseas.",
		Exit:        apitypes.PackExitOverseas,
		Rules:       overseasRules("OpenAI", "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com"),
	},
	{
		Name: "Cursor",
		Description: "Cursor editor + Agent/tools: permit official hosts; Agent streaming " +
			"(api5.*) goes direct for stability, editor/API/CDN via Overseas. " +
			"Under TUN these must be permitted or the IDE agent hangs. Re-apply the pack to refresh.",
		Exit: apitypes.PackExitMixed,
		// More-specific matchers first: domain_suffix api5.cursor.sh must beat
		// the broad cursor.sh Overseas rule (first match wins).
		Rules: concatRules(
			directRules("Cursor", "api5.cursor.sh"),
			overseasRules("Cursor",
				"cursor.com", "cursor.sh",
				"cursorapi.com", "cursor-cdn.com", "cursorvm.com",
				"todesktop.com",
				"anysphere-binaries.s3.us-east-1.amazonaws.com",
			),
		),
	},
	{
		Name:        "AI (other)",
		Description: "Gemini / Grok / Perplexity / …: permit + route via proxy (Auto).",
		Exit:        apitypes.PackExitAuto,
		Rules: proxyRules("AI (other)",
			"gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com", "deepmind.com",
			"x.ai", "grok.com", "perplexity.ai",
			"mistral.ai", "cohere.com", "groq.com", "poe.com",
			"huggingface.co", "hf.co", "midjourney.com", "suno.com",
			"ollama.com"),
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

func packRules(pack, action, node string, domains ...string) []apitypes.CustomRule {
	p := true
	out := make([]apitypes.CustomRule, 0, len(domains))
	for _, d := range domains {
		out = append(out, apitypes.CustomRule{
			Match:   apitypes.CustomMatchDomainSuffix,
			Value:   d,
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

func overseasRules(pack string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionProxy, proxygroups.OverseasGroupTag, domains...)
}

func directRules(pack string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionDirect, "", domains...)
}
