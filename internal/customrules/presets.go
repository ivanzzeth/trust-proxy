package customrules

import "github.com/ivanzzeth/trust-proxy/pkg/apitypes"

// Presets are curated Allow packs a user can import in one click. Applying a
// preset Adds each rule tagged with Pack=<Name>, Enabled=true. Matches use
// domain_suffix (covers subdomains). These are convenience bundles, not an
// exhaustive list — users edit/extend them like any custom rule afterwards.
var Presets = []apitypes.PackPreset{
	{
		Name:        "Dev",
		Description: "GitHub / npm / PyPI / Go / Docker registries via the proxy.",
		Rules: proxyRules("Dev",
			"github.com", "githubusercontent.com", "githubassets.com", "ghcr.io",
			"npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org",
			"pkg.go.dev", "proxy.golang.org", "sum.golang.org",
			"docker.io", "docker.com"),
	},
	{
		Name:        "Google",
		Description: "Google services + YouTube via the proxy.",
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

func packRules(pack, action string, domains ...string) []apitypes.CustomRule {
	out := make([]apitypes.CustomRule, 0, len(domains))
	for _, d := range domains {
		out = append(out, apitypes.CustomRule{
			Match: apitypes.CustomMatchDomainSuffix, Value: d, Action: action, Pack: pack, Enabled: true,
		})
	}
	return out
}

func proxyRules(pack string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionProxy, domains...)
}

func directRules(pack string, domains ...string) []apitypes.CustomRule {
	return packRules(pack, apitypes.CustomActionDirect, domains...)
}
