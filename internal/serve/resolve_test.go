package serve

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/cache"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
)

// switchable is an upstream that answers, or fails, on demand.
type switchable struct {
	mu   sync.Mutex
	down bool
}

func (u *switchable) set(down bool) { u.mu.Lock(); u.down = down; u.mu.Unlock() }

func (u *switchable) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.down {
		return nil, errors.New("upstream unreachable")
	}
	resp := new(dns.Msg).SetReply(q)
	rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.7")
	resp.Answer = append(resp.Answer, rr)
	return resp, nil
}

func TestServer_ServesStaleWhenUpstreamsFail(t *testing.T) {
	up, _ := startZone(t, nil)
	s, _ := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}})

	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	upstream := &switchable{}
	s.cache = cache.New(100, cache.WithClock(clock))
	s.exchanger = upstream

	ask := func() *dns.Msg {
		q := new(dns.Msg).SetQuestion("www.example.com.", dns.TypeA)
		q.SetEdns0(1232, false)
		return s.answerDNS(t.Context(), "udp", netip.MustParseAddr("192.0.2.50"), q)
	}

	if resp := ask(); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("first answer: %v", resp)
	}

	// The answer expires, and then the upstream goes down.
	advance(2 * time.Minute)
	upstream.set(true)

	resp := ask()
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 || resp.Answer[0].Header().Ttl != cache.StaleTTL {
		t.Fatalf("with the upstream down: %v, want the stale answer with TTL %d", resp, cache.StaleTTL)
	}
	var ede *dns.EDNS0_EDE
	for _, o := range resp.IsEdns0().Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok {
			ede = e
		}
	}
	if ede == nil || ede.InfoCode != dns.ExtendedErrorCodeStaleAnswer {
		t.Errorf("stale answer's EDE = %v, want Stale Answer", ede)
	}
	if page := s.qlog.Query(querylog.Filter{Limit: 1}); page.Entries[0].Reason != "stale" {
		t.Errorf("logged reason %q, want stale", page.Entries[0].Reason)
	}

	// Past the stale window, it's a failure again.
	advance(cache.MaxStale)
	if resp := ask(); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("past the stale window: %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}

	// Once the upstream is back, answers are fresh.
	upstream.set(false)
	if resp := ask(); resp.Answer[0].Header().Ttl != 60 {
		t.Errorf("after recovery: TTL %d, want a fresh 60", resp.Answer[0].Header().Ttl)
	}
}
