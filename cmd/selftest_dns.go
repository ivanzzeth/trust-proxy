package cmd

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// stubResolver is a loopback DNS server that answers every A query with the
// given address and records which names it was asked for. Two of them let the
// self-test prove WHICH resolver a lookup went to — the whole point of the
// "DNS follows route" split: a direct-routed domain must be resolved by the
// resolver we dial directly, not by the one behind the exit node (whose answers
// carry the exit node's geography).
//
// Loopback-only, so it is unaffected by whatever TUN/proxy the host machine is
// running — the self-test stays hermetic.
type stubResolver struct {
	answer string
	udp    *dns.Server
	tcp    *dns.Server

	mu   sync.Mutex
	seen map[string]int
}

func newStubResolver(port int, answer string) *stubResolver {
	s := &stubResolver{answer: answer, seen: map[string]int{}}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			s.record(q.Name)
			if q.Qtype != dns.TypeA {
				continue // AAAA & co: NOERROR with no answer, so A is used
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, s.answer))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})
	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: h}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: h}
	go func() { _ = s.udp.ListenAndServe() }()
	go func() { _ = s.tcp.ListenAndServe() }()
	return s
}

func (s *stubResolver) record(name string) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	s.mu.Lock()
	s.seen[n]++
	s.mu.Unlock()
}

// saw reports whether this resolver was asked for the given host.
func (s *stubResolver) saw(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[strings.ToLower(host)] > 0
}

func (s *stubResolver) reset() {
	s.mu.Lock()
	s.seen = map[string]int{}
	s.mu.Unlock()
}

func (s *stubResolver) close() {
	_ = s.udp.Shutdown()
	_ = s.tcp.Shutdown()
}

// waitResolver blocks until the stub is actually accepting queries (both
// listeners are started in goroutines), so a case can't race the first lookup.
func waitResolver(port int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < 50; i++ {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
