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
			"huggingface.co", "hf.co", "midjourney.com", "suno.com"),
	},
	{
		Name:        "Dev",
		Description: "GitHub ecosystem via geosite-github (community-maintained). Covers github.com, raw/usercontent, ghcr, Copilot hosts, etc. without a hand-maintained domain list.",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRS("geosite-github"),
		// npm/pypi/go/docker stay as custom rules — no single clean geosite tag.
		Rules: proxyRules("Dev",
			"npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org",
			"pkg.go.dev", "proxy.golang.org", "sum.golang.org",
			"docker.io", "docker.com"),
	},
	{
		Name:        "Telegram",
		Description: "Telegram via geosite-telegram (apps + media CDN). Community list stays current.",
		Exit:        apitypes.PackExitAuto,
		RuleSets:    catalogRS("geosite-telegram"),
		Rules:       []apitypes.CustomRule{}, // non-nil so JSON is [] not null (UI reads .length)
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

func packRules(pack, action, node string, domains ...string) []apitypes.CustomRule {
	out := make([]apitypes.CustomRule, 0, len(domains))
	for _, d := range domains {
		out = append(out, apitypes.CustomRule{
			Match: apitypes.CustomMatchDomainSuffix, Value: d, Action: action, Node: node, Pack: pack, Enabled: true,
		})
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
