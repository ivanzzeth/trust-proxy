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
// Geofencing: several services block by the exit country's jurisdiction (a
// commercial block, not the GFW). Anthropic/OpenAI refuse Hong Kong + mainland
// China; Cursor refuses HK/TW/CN for its Claude models. Those packs egress via
// the shared "Overseas" group (a urltest over every node whose country is NOT
// excluded — default HK/MO/CN), so traffic fails over across allowed regions and
// can NEVER land on a blocked one. It degrades gracefully: if the exclusion
// removes no node (you have no HK/CN nodes) the Overseas group isn't built and
// the rule falls back to the default proxy (Auto = fastest, already safe).
// Services with no geofence stay on plain proxy (auto). Research behind these:
// Anthropic/OpenAI block HK+CN; Gemini/Grok/Perplexity/Mistral/etc. have none.
var Presets = []apitypes.PackPreset{
	{
		Name:        "Claude",
		Description: "Anthropic Claude (web, API, Claude Code) via the Overseas group. Anthropic blocks Hong Kong / mainland China, so this routes through your allowed overseas nodes (never HK/CN) and fails over among them. Tune the excluded regions in Proxies → group settings.",
		Exit:        apitypes.PackExitOverseas,
		Rules:       overseasRules("Claude", "anthropic.com", "claude.ai", "claude.com"),
	},
	{
		Name:        "OpenAI",
		Description: "OpenAI ChatGPT / API / Sora via the Overseas group. OpenAI cut off Hong Kong + mainland China in 2024 and flags datacenter IPs — this keeps traffic on allowed overseas nodes (a clean residential one is best).",
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
		Description: "GitHub / Copilot / npm / PyPI / Go / Docker registries via the proxy (fastest). No region lock (trade-control embargoed regions aside).",
		Exit:        apitypes.PackExitAuto,
		Rules: proxyRules("Dev",
			"github.com", "githubusercontent.com", "githubassets.com", "ghcr.io", "githubcopilot.com",
			"npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org",
			"pkg.go.dev", "proxy.golang.org", "sum.golang.org",
			"docker.io", "docker.com"),
	},
	{
		Name:        "Telegram",
		Description: "Telegram apps + media via the proxy (fastest).",
		Exit:        apitypes.PackExitAuto,
		Rules:       proxyRules("Telegram", "telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com"),
	},
	{
		Name:        "Streaming",
		Description: "Netflix / Disney+ / HBO / Spotify / Twitch via the proxy (fastest). Content library depends on the exit country; these services also block datacenter IPs — a residential node is best. Re-pin to your preferred library's country if needed.",
		Exit:        apitypes.PackExitAuto,
		Rules: proxyRules("Streaming",
			"netflix.com", "nflxvideo.net", "disneyplus.com", "disney-plus.net",
			"hbomax.com", "max.com", "spotify.com", "scdn.co", "twitch.tv", "ttvnw.net"),
	},
	{
		Name:        "Google",
		Description: "Google services + YouTube via the proxy (fastest).",
		Exit:        apitypes.PackExitAuto,
		Rules: proxyRules("Google",
			"google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
			"ggpht.com", "youtube.com", "ytimg.com", "googlevideo.com"),
	},
	{
		Name:        "Apple",
		Description: "Apple / iCloud, routed direct (usually best from CN).",
		Exit:        apitypes.PackExitDirect,
		Rules: directRules("Apple",
			"apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com", "apple-cloudkit.com"),
	},
	{
		Name:        "China-direct",
		Description: "Common mainland-China sites, routed direct. For full CN coverage prefer the geosite-cn rule set.",
		Exit:        apitypes.PackExitDirect,
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
