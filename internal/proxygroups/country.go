package proxygroups

import "strings"

// Country guesses a node's country from its tag (the airport's node name),
// which conventionally carries a flag emoji, a country name (zh/en), or an ISO
// code. Returns an ISO-3166 alpha-2 code (upper-case) or "" if unknown. This is
// the zero-dependency approach clash/mihomo also use — no geoip lookup.
func Country(tag string) string {
	if c := flagCountry(tag); c != "" {
		return c
	}
	low := strings.ToLower(tag)
	// Names / CJK: safe as substrings (multi-char, rarely collide).
	for _, kw := range names {
		if strings.Contains(low, kw.match) {
			return kw.code
		}
	}
	// Bare 2-letter codes: only as a standalone token, never inside a word
	// ("node" must not match "de", "status" must not match "us").
	for _, run := range asciiRuns(low) {
		if iso, ok := codeMap[run]; ok {
			return iso
		}
	}
	return ""
}

// flagCountry decodes the first regional-indicator flag emoji (two symbols in
// U+1F1E6..U+1F1FF) into its ISO code.
func flagCountry(s string) string {
	runes := []rune(s)
	for i := 0; i+1 < len(runes); i++ {
		a, b := runes[i], runes[i+1]
		if a >= 0x1F1E6 && a <= 0x1F1FF && b >= 0x1F1E6 && b <= 0x1F1FF {
			return string([]byte{byte('A' + (a - 0x1F1E6)), byte('A' + (b - 0x1F1E6))})
		}
	}
	return ""
}

// asciiRuns splits a lower-cased string into maximal [a-z] runs (tokens).
func asciiRuns(s string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
			if start < 0 {
				start = i
			}
		} else if start >= 0 {
			out = append(out, s[start:i])
			start = -1
		}
	}
	return out
}

// CountryName returns a display label (flag + code) for a code, or the code.
func CountryName(code string) string {
	if len(code) != 2 {
		return code
	}
	var flag []rune
	for _, r := range strings.ToUpper(code) {
		if r < 'A' || r > 'Z' {
			return code
		}
		flag = append(flag, 0x1F1E6+(r-'A'))
	}
	return string(flag) + " " + strings.ToUpper(code)
}

// names are matched as case-insensitive substrings (multi-char / CJK, safe).
// Order matters: longer / more-specific first.
var names = []struct{ match, code string }{
	{"hong kong", "HK"}, {"hongkong", "HK"}, {"香港", "HK"}, {"港", "HK"},
	{"taiwan", "TW"}, {"台湾", "TW"}, {"臺灣", "TW"}, {"台灣", "TW"}, {"台", "TW"},
	{"singapore", "SG"}, {"新加坡", "SG"}, {"狮城", "SG"},
	{"japan", "JP"}, {"日本", "JP"}, {"东京", "JP"}, {"大阪", "JP"},
	{"korea", "KR"}, {"韩国", "KR"}, {"首尔", "KR"},
	{"united states", "US"}, {"america", "US"}, {"美国", "US"}, {"美國", "US"}, {"洛杉矶", "US"}, {"usa", "US"},
	{"united kingdom", "GB"}, {"britain", "GB"}, {"英国", "GB"}, {"伦敦", "GB"},
	{"germany", "DE"}, {"德国", "DE"}, {"法兰克福", "DE"},
	{"france", "FR"}, {"法国", "FR"},
	{"netherlands", "NL"}, {"荷兰", "NL"},
	{"canada", "CA"}, {"加拿大", "CA"},
	{"australia", "AU"}, {"澳大利亚", "AU"}, {"悉尼", "AU"},
	{"russia", "RU"}, {"俄罗斯", "RU"}, {"莫斯科", "RU"},
	{"india", "IN"}, {"印度", "IN"},
	{"malaysia", "MY"}, {"马来西亚", "MY"}, {"吉隆坡", "MY"},
	{"thailand", "TH"}, {"泰国", "TH"}, {"曼谷", "TH"},
	{"vietnam", "VN"}, {"越南", "VN"},
	{"philippines", "PH"}, {"菲律宾", "PH"},
	{"indonesia", "ID"}, {"印尼", "ID"},
	{"turkey", "TR"}, {"土耳其", "TR"},
	{"argentina", "AR"}, {"阿根廷", "AR"},
	{"brazil", "BR"}, {"巴西", "BR"},
	{"china", "CN"}, {"中国", "CN"}, {"回国", "CN"},
}

// codeMap maps a bare lower-case token to its ISO code (UK -> GB).
var codeMap = map[string]string{
	"hk": "HK", "tw": "TW", "sg": "SG", "jp": "JP", "kr": "KR", "us": "US",
	"uk": "GB", "gb": "GB", "de": "DE", "fr": "FR", "nl": "NL", "ca": "CA",
	"au": "AU", "ru": "RU", "in": "IN", "my": "MY", "th": "TH", "vn": "VN",
	"ph": "PH", "id": "ID", "tr": "TR", "ar": "AR", "br": "BR", "cn": "CN",
}
