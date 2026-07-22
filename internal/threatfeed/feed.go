// Package threatfeed periodically fetches public threat-intel indicator lists
// (default: abuse.ch Feodo Tracker C2 IP blocklist, CC0, no auth) and loads them
// into the detection engine, so egress to a known C2/botnet IP raises an alert
// (and is dropped when auto-block is on) even if the destination was whitelisted.
package threatfeed

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultFeeds are no-auth, permissively-licensed indicator lists (one
// indicator per line, `#` comments). Feodo = botnet C2 IPs; URLhaus = malware
// distribution hosts (we take the host part as a domain/IP indicator).
var DefaultFeeds = []string{
	"https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}

// Sink receives the parsed indicators (gateway detection engine).
type Sink interface {
	SetFeedThreats(domains, ips []string)
}

// Loader fetches feeds on an interval and pushes indicators into the sink.
type Loader struct {
	urls     []string
	interval time.Duration
	sink     Sink
	hc       *http.Client
	logf     func(string, ...any)
}

// New builds a loader. Empty urls -> DefaultFeeds; interval <= 0 -> 12h.
func New(sink Sink, urls []string, interval time.Duration, logf func(string, ...any)) *Loader {
	if len(urls) == 0 {
		urls = DefaultFeeds
	}
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Loader{
		urls:     urls,
		interval: interval,
		sink:     sink,
		hc:       &http.Client{Timeout: 30 * time.Second},
		logf:     logf,
	}
}

// Run does an immediate refresh, then refreshes on the interval until ctx is
// cancelled. Intended to be launched in its own goroutine.
func (l *Loader) Run(ctx context.Context) {
	l.refresh(ctx)
	t := time.NewTicker(l.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.refresh(ctx)
		}
	}
}

func (l *Loader) refresh(ctx context.Context) {
	domainSet := map[string]struct{}{}
	ipSet := map[string]struct{}{}
	ok := 0
	for _, u := range l.urls {
		ds, ips, err := l.fetch(ctx, u)
		if err != nil {
			l.logf("threatfeed: %s: %v", u, err)
			continue
		}
		ok++
		for _, d := range ds {
			domainSet[d] = struct{}{}
		}
		for _, ip := range ips {
			ipSet[ip] = struct{}{}
		}
	}
	if ok == 0 {
		l.logf("threatfeed: all %d feed(s) failed; keeping previous indicators", len(l.urls))
		return
	}
	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	l.sink.SetFeedThreats(domains, ips)
	l.logf("threatfeed: loaded %d IP + %d domain indicator(s) from %d/%d feed(s)", len(ips), len(domains), ok, len(l.urls))
}

// fetch downloads one list and splits it into domains vs IPs. Lines that are an
// IP (or CIDR) go to ips; anything host-like goes to domains. URLs (http://…)
// are reduced to their host.
func (l *Loader) fetch(ctx context.Context, url string) (domains, ips []string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "trust-proxy-threatfeed/1.0")
	resp, err := l.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// CSV feeds: take the first field.
		if i := strings.IndexAny(line, ", \t"); i > 0 {
			line = line[:i]
		}
		line = strings.Trim(line, "\"")
		// URL -> host
		if strings.Contains(line, "://") {
			if h := hostFromURL(line); h != "" {
				line = h
			}
		}
		if line == "" {
			continue
		}
		if isIPOrCIDR(line) {
			ips = append(ips, line)
		} else {
			domains = append(domains, strings.ToLower(line))
		}
	}
	return domains, ips, sc.Err()
}

func isIPOrCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}

func hostFromURL(raw string) string {
	rest := raw[strings.Index(raw, "://")+3:]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if h, _, err := net.SplitHostPort(rest); err == nil {
		return h
	}
	return rest
}
