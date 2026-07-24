package customrules

import (
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Presets are curated Allow packs a user can import in one click.
//
// Prefer RuleSets (geosite-*) for broad services — the community list covers
// companions (gvt2, CDN hosts, …) so we stop hand-maintaining domain tables.
// Keep custom Rules when egress must pin a group (Overseas) or when no clean
// geosite category exists.
//
// Geofencing: Anthropic/OpenAI refuse HK+CN; Cursor refuses HK/TW/CN for Claude
// models. Those packs keep domain Rules with Node=Overseas. Broad packs
// (Google/Dev/…) bind catalog rule sets as allow-proxy / allow-direct.
var Presets = []apitypes.PackPreset{
	{
		Name:        "Claude",
		Description: "Anthropic Claude (web, API, Claude Code) via the Overseas group. Anthropic blocks Hong Kong / mainland China, so this routes through your allowed overseas nodes (never HK/CN) and fails over among them. Tune the excluded regions in Proxies → group settings.",
		Exit:        apitypes.PackExitOverseas,
		Rules:       overseasRules("Claude", "anthropic.com", "claude.ai", "claude.com"),
	},
	{
		Name:        "OpenAI",
		Description: "OpenAI ChatGPT / API / Sora via the Overseas group. OpenAI cut off Hong Kong + mainland China in 2024 and flags datacenter IPs — this keeps traffic on allowed overseas nodes (a residential one is best).",
		Exit:        apitypes.PackExitOverseas,
		Rules:       overseasRules("OpenAI", "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com"),
	},
	{
		Name:        "Cursor",
		Description: "Cursor editor via the Overseas group. Cursor enforces the upstream provider's region: HK/TW/CN exits get \"provider doesn't serve your region\" for Claude models. NOTE: the shared Overseas group excludes HK/CN but not Taiwan — if Cursor's Claude models fail, add TW to the excluded regions or make a US-only group.",
		Exit:        apitypes.PackExitOverseas,
		Rules:       overseasRules("Cursor", "cursor.com", "cursor.sh"),
	},
	{
		Name:        "AI (other)",
		Description: "Gemini / Grok / Perplexity / Mistral / Cohere / Groq / Poe / HuggingFace / Midjourney / Suno via the proxy (fastest). These have no meaningful region lock — any supported exit works.",
		Exit:        apitypes.PackExitAuto,
		Rules: proxyRules("AI (other)",
			"gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com", "deepmind.com",
			"x.ai", "grok.com", "perplexity.ai",
			"mistral.ai", "cohere.com", "groq.com", "poe.com",
			"huggingface.co", "hf.co", "midjourney.com", "suno.com",
			"ollama.com"),
	},
	{
		Name: "Dev",
		Description: "GitHub + Microsoft-dev (VS Code / NuGet / …) via geosite, plus package registries. " +
			"Custom rules pin Git SSH hosts and GitHub git IP ranges from api.github.com/meta — under TUN, " +
			"git often dials by IP with no SNI, so domain-only allow is not enough. " +
			"VS Code update hosts (code.visualstudio.com) are also pinned — they are not always in geosite-github.",
		Exit:     apitypes.PackExitAuto,
		RuleSets: catalogRS("geosite-github", "geosite-microsoft-dev"),
		Rules: concatRules(
			// Explicit Git SSH / forge hosts first (ordered L4).
			proxyRules("Dev", "ssh.github.com", "github.com", "githubusercontent.com"),
			proxyCIDRs("Dev", githubGitCIDRs...),
			// VS Code update CDN (seen blocked under TUN when only geosite-github was on).
			// vscode.download.prss.microsoft.com is in v2fly microsoft list; code.visualstudio.com is the update host.
			proxyRules("Dev", "code.visualstudio.com", "vscode.download.prss.microsoft.com"),
			// Registries without a clean geosite tag.
			proxyRules("Dev",
				"npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org",
				"pkg.go.dev", "proxy.golang.org", "sum.golang.org",
				"docker.io", "docker.com"),
		),
	},
	{
		Name: "Telegram",
		Description: "Telegram via geosite-telegram (apps + media CDN) plus official DC IP ranges " +
			"from core.telegram.org/resources/cidr.txt. Desktop often dials DCs by IP with no SNI — " +
			"domain-only allow leaves MTProto/HTTPS edges blocked under TUN.",
		Exit:     apitypes.PackExitAuto,
		RuleSets: catalogRS("geosite-telegram"),
		Rules:    proxyCIDRs("Telegram", telegramCIDRs...),
	},
	{
		Name:        "Slack",
		Description: "Slack via geosite-slack (slack.com, slack-edge, slackb, …). Community list from SagerNet/sing-geosite.",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRS("geosite-slack"),
		Rules:       []apitypes.CustomRule{},
	},
	{
		Name:        "Notion",
		Description: "Notion via geosite-notion. Community list from SagerNet/sing-geosite.",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRS("geosite-notion"),
		Rules:       []apitypes.CustomRule{},
	},
	{
		Name:        "X",
		Description: "X (Twitter) via geosite-twitter — x.com, twitter.com, t.co, twimg CDN, API hosts, etc.",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRS("geosite-twitter"),
		Rules:       []apitypes.CustomRule{},
	},
	{
		Name:        "Streaming",
		Description: "Netflix + Spotify via geosite rule sets. Disney+/HBO/Twitch stay as custom suffixes (no single clean geosite tag). Library depends on exit country; datacenter IPs are often blocked.",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRS("geosite-netflix", "geosite-spotify"),
		Rules: proxyRules("Streaming",
			"disneyplus.com", "disney-plus.net",
			"hbomax.com", "max.com",
			"twitch.tv", "ttvnw.net"),
	},
	{
		Name: "Google",
		Description: "Google + YouTube via geosite-google / geosite-youtube (community-maintained). " +
			"Covers companions (gvt2/gvt3, beacons, SafeBrowsing, …) so Chrome tabs stop stalling on ACL blocks. " +
			"No hand-maintained domain table.",
		Exit:     apitypes.PackExitAuto,
		RuleSets: catalogRS("geosite-google", "geosite-youtube"),
		Rules:    []apitypes.CustomRule{},
	},
	{
		Name:        "Apple",
		Description: "Apple / iCloud via geosite-apple, routed direct (usually best from CN).",
		Exit:        apitypes.PackExitDirect,
		RuleSets:    catalogRS("geosite-apple"),
		Rules:       []apitypes.CustomRule{},
	},
	{
		Name: "China-direct",
		Description: "Mainland China coverage via geosite-cn (community-maintained). " +
			"Prefer this over a short domain list — geosite-cn includes baidu CDN hosts, etc.",
		Exit:     apitypes.PackExitDirect,
		RuleSets: catalogRS("geosite-cn"),
		Rules:    []apitypes.CustomRule{},
	},
}

// catalogRS builds PackRuleSet entries; role is taken from the catalog's
// SuggestedRole at import time when left empty.
func catalogRS(tags ...string) []apitypes.PackRuleSet {
	out := make([]apitypes.PackRuleSet, 0, len(tags))
	for _, t := range tags {
		out = append(out, apitypes.PackRuleSet{CatalogTag: t})
	}
	return out
}

// telegramCIDRs are Telegram's published DC ranges
// (https://core.telegram.org/resources/cidr.txt). Desktop clients commonly
// dial these by IP; geosite-telegram alone is not enough under TUN.
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

// githubGitCIDRs are GitHub's published git SSH/HTTPS edge ranges
// (https://api.github.com/meta → "git"). Needed because TUN clients often
// connect to these IPs directly after DNS — domain_suffix rules never see a
// name. Refresh when GitHub announces new edges (spot-check meta).
var githubGitCIDRs = []string{
	// Classic GitHub AS
	"192.30.252.0/22",
	"185.199.108.0/22",
	"140.82.112.0/20",
	"143.55.64.0/20",
	"2a0a:a440::/29",
	"2606:50c0::/32",
	// Azure front doors (often hit from CN); /32s as published
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
	out := make([]apitypes.CustomRule, 0, len(domains))
	for _, d := range domains {
		out = append(out, apitypes.CustomRule{
			Match: apitypes.CustomMatchDomainSuffix, Value: d, Action: action, Node: node, Pack: pack, Enabled: true,
		})
	}
	return out
}

func proxyCIDRs(pack string, cidrs ...string) []apitypes.CustomRule {
	out := make([]apitypes.CustomRule, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, apitypes.CustomRule{
			Match: apitypes.CustomMatchIPCIDR, Value: c, Action: apitypes.CustomActionProxy, Pack: pack, Enabled: true,
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

// proxyRules route via the default proxy group (Auto = fastest); no region pin.
func proxyRules(pack string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionProxy, "", domains...)
}

// overseasRules route via the shared Overseas group (all nodes whose country is
// not excluded — default HK/MO/CN). When that group isn't built (nothing to
// exclude), the engine falls back to the default proxy group, so the domain is
// always allowed. Used for services that geofence out HK/CN.
func overseasRules(pack string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionProxy, proxygroups.OverseasGroupTag, domains...)
}

func directRules(pack string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionDirect, "", domains...)
}
