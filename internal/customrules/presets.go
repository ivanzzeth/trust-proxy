package customrules

import (
	"github.com/ivanzzeth/trust-proxy/internal/proxygroups"
	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Presets are curated Allow packs a user can import in one click. Applying a
// preset Adds each rule tagged with Pack=<Name>, Enabled=true. Matches use
// domain_suffix (covers subdomains). These are convenience bundles, not an
// exhaustive list — users edit/extend them like any custom rule afterwards.
//
// Region pinning: several services geofence by the exit country's jurisdiction
// (a commercial block, not the GFW). Anthropic/OpenAI refuse Hong Kong/mainland
// China; Cursor refuses HK/TW/CN for its Claude models. For those packs we emit
// a proxy rule pinned to a recommended country GROUP (e.g. "🇯🇵 JP") instead of
// the plain proxy selector. The pin degrades gracefully: if the user has no
// node in that country (so the group doesn't exist), the engine falls back to
// the default `proxy` group (Auto = fastest) — the domain is still allowed, just
// not region-pinned. Services with no geofence stay on plain proxy (auto).
// See the research behind these choices: Anthropic/OpenAI block HK+CN;
// Gemini/Grok/Perplexity/Copilot/Mistral/etc. have no meaningful region lock.
var Presets = []apitypes.PackPreset{
	{
		Name:        "Claude",
		Description: "Anthropic Claude (web, API, Claude Code) via Japan. Anthropic blocks Hong Kong / mainland China; Japan is supported with the lowest latency. Falls back to fastest if you have no JP node. US/SG/TW also work — edit the rules to re-pin.",
		Region:      "JP",
		Rules:       regionRules("Claude", "JP", "anthropic.com", "claude.ai", "claude.com"),
	},
	{
		Name:        "OpenAI",
		Description: "OpenAI ChatGPT / API / Sora via Japan. OpenAI cut off Hong Kong + mainland China in 2024 and flags datacenter IPs — prefer a clean residential JP (or US) node. Falls back to fastest if you have no JP node.",
		Region:      "JP",
		Rules:       regionRules("OpenAI", "JP", "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com"),
	},
	{
		Name:        "Cursor",
		Description: "Cursor editor via the US. Cursor enforces the upstream model provider's region: users exiting HK/TW/CN get \"provider doesn't serve your region\" for Claude models. US works for the account + all models. Falls back to fastest if you have no US node.",
		Region:      "US",
		Rules:       regionRules("Cursor", "US", "cursor.com", "cursor.sh"),
	},
	{
		Name:        "AI (other)",
		Description: "Gemini / Grok / Perplexity / Mistral / Cohere / Groq / Poe / HuggingFace / Midjourney / Suno via the proxy (fastest). These have no meaningful region lock — any supported exit works.",
		Rules: proxyRules("AI (other)",
			"gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com", "deepmind.com",
			"x.ai", "grok.com", "perplexity.ai",
			"mistral.ai", "cohere.com", "groq.com", "poe.com",
			"huggingface.co", "hf.co", "midjourney.com", "suno.com"),
	},
	{
		Name:        "Dev",
		Description: "GitHub / Copilot / npm / PyPI / Go / Docker registries via the proxy (fastest). No region lock (trade-control embargoed regions aside).",
		Region:      "",
		Rules: proxyRules("Dev",
			"github.com", "githubusercontent.com", "githubassets.com", "ghcr.io", "githubcopilot.com",
			"npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org",
			"pkg.go.dev", "proxy.golang.org", "sum.golang.org",
			"docker.io", "docker.com"),
	},
	{
		Name:        "Telegram",
		Description: "Telegram apps + media via the proxy (fastest).",
		Rules:       proxyRules("Telegram", "telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com"),
	},
	{
		Name:        "Streaming",
		Description: "Netflix / Disney+ / HBO / Spotify / Twitch via the proxy (fastest). Content library depends on the exit country; these services also block datacenter IPs — a residential node is best. Re-pin to your preferred library's country if needed.",
		Rules: proxyRules("Streaming",
			"netflix.com", "nflxvideo.net", "disneyplus.com", "disney-plus.net",
			"hbomax.com", "max.com", "spotify.com", "scdn.co", "twitch.tv", "ttvnw.net"),
	},
	{
		Name:        "Google",
		Description: "Google services + YouTube via the proxy (fastest).",
		Rules: proxyRules("Google",
			"google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
			"ggpht.com", "youtube.com", "ytimg.com", "googlevideo.com"),
	},
	{
		Name:        "Apple",
		Description: "Apple / iCloud, routed direct (usually best from CN).",
		Rules: directRules("Apple",
			"apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com", "apple-cloudkit.com"),
	},
	{
		Name:        "China-direct",
		Description: "Common mainland-China sites, routed direct. For full CN coverage prefer the geosite-cn rule set.",
		Rules: directRules("China-direct",
			"qq.com", "weixin.qq.com", "taobao.com", "tmall.com", "jd.com",
			"bilibili.com", "aliyun.com", "aliyuncs.com", "alicdn.com", "163.com", "baidu.com"),
	},
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

// regionRules route via the proxy but PREFER the country group for the given
// ISO2 code (e.g. JP -> "🇯🇵 JP"). The engine falls back to the default proxy
// group when that country group doesn't exist (no such node), so the domain is
// always allowed — just region-pinned when possible.
func regionRules(pack, region string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionProxy, proxygroups.CountryName(region), domains...)
}

func directRules(pack string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionDirect, "", domains...)
}
