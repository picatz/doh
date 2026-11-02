package serve

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/policy"
)

// answering is an upstream that answers every A query at once, with
// 192.0.2.7, for benchmarks.
type answering struct{}

func (answering) Exchange(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg).SetReply(q)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   []byte{192, 0, 2, 7},
	})
	return resp, nil
}

// newBenchServer returns a server whose default profile has every
// protection that needs no network on, a deny list, and the query log,
// answering from a fake upstream, quietly.
func newBenchServer(b *testing.B, configure ...func(*Config)) *Server {
	b.Helper()
	deny := make([]string, 1000)
	for i := range deny {
		deny[i] = "blocked" + strconv.Itoa(i) + ".example"
	}
	s, _ := newPolicyServer(b, "192.0.2.53", &policy.Policy{Profiles: []policy.Profile{{
		ID:         "default",
		Security:   policy.Security{Rebinding: true, Homograph: true, Tunneling: true, Bypass: true},
		Deny:       deny,
		BlockTLDs:  []string{"zip"},
		SafeSearch: true,
	}}}, configure...)
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	s.exchanger = answering{}
	return s
}

// benchQueries returns n A queries for distinct names.
func benchQueries(n int, name func(int) string) []*dns.Msg {
	qs := make([]*dns.Msg, n)
	for i := range qs {
		qs[i] = new(dns.Msg).SetQuestion(name(i), dns.TypeA)
		qs[i].SetEdns0(1232, false)
	}
	return qs
}

// BenchmarkResolve measures a plain DNS query through the whole path:
// choosing a profile, every filter check, the cache or the upstream, the
// answer checks, and the query log.
func BenchmarkResolve(b *testing.B) {
	client := netip.MustParseAddr("192.168.1.20")

	b.Run("cached", func(b *testing.B) {
		s := newBenchServer(b)
		qs := benchQueries(1000, func(i int) string { return "www.site" + strconv.Itoa(i) + ".com." })
		for _, q := range qs {
			s.answerDNS(b.Context(), "udp", client, q.Copy())
		}
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			if resp := s.answerDNS(b.Context(), "udp", client, qs[i%len(qs)].Copy()); resp.Rcode != dns.RcodeSuccess {
				b.Fatal(resp)
			}
			i++
		}
	})

	b.Run("upstream", func(b *testing.B) {
		s := newBenchServer(b, func(c *Config) { c.Cache.Disabled = true })
		q := benchQueries(1, func(int) string { return "www.example.com." })[0]
		b.ReportAllocs()
		for b.Loop() {
			if resp := s.answerDNS(b.Context(), "udp", client, q.Copy()); resp.Rcode != dns.RcodeSuccess {
				b.Fatal(resp)
			}
		}
	})

	b.Run("blocked", func(b *testing.B) {
		s := newBenchServer(b)
		qs := benchQueries(1000, func(i int) string { return "ads.blocked" + strconv.Itoa(i) + ".example." })
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			if resp := s.answerDNS(b.Context(), "udp", client, qs[i%len(qs)].Copy()); resp.Rcode != dns.RcodeNameError {
				b.Fatal(resp)
			}
			i++
		}
	})

	b.Run("cached/parallel", func(b *testing.B) {
		s := newBenchServer(b)
		qs := benchQueries(1000, func(i int) string { return "www.site" + strconv.Itoa(i) + ".com." })
		for _, q := range qs {
			s.answerDNS(b.Context(), "udp", client, q.Copy())
		}
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				s.answerDNS(context.Background(), "udp", client, qs[i%len(qs)].Copy())
				i++
			}
		})
	})
}
