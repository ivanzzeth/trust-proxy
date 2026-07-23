package ruleset

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"

	"github.com/ivanzzeth/trust-proxy/pkg/apitypes"
)

// Entry is one decoded rule-set rule, flattened to (kind, value) so the console
// can list and search the contents of an imported rule-set.
type Entry struct {
	Kind  string `json:"kind"` // domain | domain_suffix | domain_keyword | domain_regex | ip_cidr
	Value string `json:"value"`
}

// Decode fetches a rule-set (remote URL or local path) and flattens it to
// entries. get lets the caller control how remote bytes are fetched (e.g. via
// the gateway proxy); nil uses a plain direct client. Binary (.srs) is decoded
// with sing-box's srs reader; source (.json) is parsed as a plain rule-set.
func Decode(rs apitypes.RuleSet, get func(url string) (io.ReadCloser, error)) ([]Entry, error) {
	var raw []byte
	if rs.Type == "local" {
		b, err := os.ReadFile(rs.Path)
		if err != nil {
			return nil, err
		}
		raw = b
	} else {
		if get == nil {
			get = directGet
		}
		rc, err := get(rs.URL)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, 64<<20))
		if err != nil {
			return nil, err
		}
		raw = b
	}

	isBinary := rs.Format == "binary" || strings.HasSuffix(rs.URL, ".srs") || strings.HasSuffix(rs.Path, ".srs")
	var set option.PlainRuleSet
	if isBinary {
		// recover=true dumps the compiled domain matcher / IP set back to the
		// original string entries (domain_suffix / ip_cidr), which is exactly what
		// we want to list; with false only the opaque compiled forms are populated.
		compat, err := srs.Read(bytes.NewReader(raw), true)
		if err != nil {
			return nil, fmt.Errorf("decode .srs: %w", err)
		}
		if set, err = compat.Upgrade(); err != nil {
			return nil, err
		}
	} else {
		var compat option.PlainRuleSetCompat
		if err := json.Unmarshal(raw, &compat); err != nil {
			return nil, fmt.Errorf("parse source rule-set: %w", err)
		}
		up, err := compat.Upgrade()
		if err != nil {
			return nil, err
		}
		set = up
	}
	return flatten(set), nil
}

func flatten(set option.PlainRuleSet) []Entry {
	var out []Entry
	for _, r := range set.Rules {
		if r.Type == "logical" {
			continue // logical rules aren't present in geosite/geoip sets
		}
		d := r.DefaultOptions
		for _, v := range d.Domain {
			out = append(out, Entry{"domain", v})
		}
		for _, v := range d.DomainSuffix {
			out = append(out, Entry{"domain_suffix", v})
		}
		for _, v := range d.DomainKeyword {
			out = append(out, Entry{"domain_keyword", v})
		}
		for _, v := range d.DomainRegex {
			out = append(out, Entry{"domain_regex", v})
		}
		for _, v := range d.IPCIDR {
			out = append(out, Entry{"ip_cidr", v})
		}
	}
	return out
}

func directGet(url string) (io.ReadCloser, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url) //nolint:noctx
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}
