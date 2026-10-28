package cache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// clock is a settable time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestCache(size int) (*Cache, *clock) {
	c := New(size)
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	c.now = clk.now
	return c, clk
}

func query(name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg).SetQuestion(name, qtype)
	q.Id = 7
	return q
}

func answer(q *dns.Msg, ttl uint32) *dns.Msg {
	resp := new(dns.Msg).SetReply(q)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP("192.0.2.1"),
	})
	return resp
}

func TestCache_GetPut(t *testing.T) {
	c, clk := newTestCache(10)
	q := query("example.com.", dns.TypeA)

	if c.Get(q) != nil {
		t.Fatal("hit on an empty cache")
	}

	c.Put(q, answer(q, 60))

	t.Run("hit decays TTLs and sets the ID", func(t *testing.T) {
		clk.advance(20 * time.Second)

		other := query("EXAMPLE.com.", dns.TypeA)
		other.Id = 99

		resp := c.Get(other)
		if resp == nil {
			t.Fatal("miss for a cached name, in different case")
		}
		if resp.Id != 99 {
			t.Errorf("got ID %d, want 99", resp.Id)
		}
		if ttl := resp.Answer[0].Header().Ttl; ttl != 40 {
			t.Errorf("got TTL %d, want 40", ttl)
		}
	})

	t.Run("hits don't change the cached copy", func(t *testing.T) {
		resp := c.Get(q)
		resp.Answer = nil

		if again := c.Get(q); again == nil || len(again.Answer) != 1 {
			t.Error("a caller's change leaked into the cache")
		}
	})

	t.Run("expires with its TTL", func(t *testing.T) {
		clk.advance(40 * time.Second)
		if c.Get(q) != nil {
			t.Error("hit after the TTL expired")
		}
		if c.Len() != 0 {
			t.Errorf("got %d entries, want the expired one evicted", c.Len())
		}
	})
}

func TestCache_Keys(t *testing.T) {
	c, _ := newTestCache(10)
	q := query("example.com.", dns.TypeA)
	c.Put(q, answer(q, 60))

	do := query("example.com.", dns.TypeA)
	do.SetEdns0(dns.DefaultMsgSize, true)

	edns := query("example.com.", dns.TypeA)
	edns.SetEdns0(dns.DefaultMsgSize, false)

	cd := query("example.com.", dns.TypeA)
	cd.CheckingDisabled = true

	ad := query("example.com.", dns.TypeA)
	ad.AuthenticatedData = true

	norec := query("example.com.", dns.TypeA)
	norec.RecursionDesired = false

	for name, other := range map[string]*dns.Msg{
		"other type":         query("example.com.", dns.TypeAAAA),
		"other name":         query("example.net.", dns.TypeA),
		"EDNS":               edns,
		"DNSSEC OK":          do,
		"checking disabled":  cd,
		"authenticated data": ad,
		"no recursion":       norec,
	} {
		if c.Get(other) != nil {
			t.Errorf("%s: hit for a different key", name)
		}
	}
}

func TestCache_Uncacheable(t *testing.T) {
	update := query("example.com.", dns.TypeSOA)
	update.Opcode = dns.OpcodeUpdate

	ecs := query("example.com.", dns.TypeA)
	ecs.SetEdns0(dns.DefaultMsgSize, false)
	ecs.IsEdns0().Option = append(ecs.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("198.51.100.0").To4(),
	})

	for name, q := range map[string]*dns.Msg{"update": update, "client subnet": ecs} {
		c, _ := newTestCache(10)
		c.Put(q, answer(q, 60))
		if c.Len() != 0 || c.Get(q) != nil {
			t.Errorf("%s: cached", name)
		}
	}

	// A cached query must not answer an update for the same name.
	c, _ := newTestCache(10)
	q := query("example.com.", dns.TypeSOA)
	c.Put(q, answer(q, 60))
	if c.Get(update) != nil {
		t.Error("update answered from the cache")
	}
}

func TestCache_Rewrites(t *testing.T) {
	c, clk := newTestCache(10)

	q := query("example.com.", dns.TypeA)
	q.SetEdns0(dns.DefaultMsgSize, false)

	resp := new(dns.Msg).SetRcode(q, dns.RcodeNameError)
	resp.Ns = append(resp.Ns, &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:     "ns.example.com.",
		Mbox:   "admin.example.com.",
		Minttl: 120,
	})
	resp.SetEdns0(dns.DefaultMsgSize, false)
	resp.IsEdns0().Option = append(resp.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708a1a2a3a4a5a6a7a8"})
	c.Put(q, resp)

	clk.advance(119 * time.Second)

	other := query("ExAmPlE.CoM.", dns.TypeA)
	other.SetEdns0(dns.DefaultMsgSize, false)

	got := c.Get(other)
	if got == nil {
		t.Fatal("miss")
	}
	if got.Question[0].Name != "ExAmPlE.CoM." {
		t.Errorf("got question %q, want the query's capitalization", got.Question[0].Name)
	}
	if ttl := got.Ns[0].Header().Ttl; ttl != 1 {
		t.Errorf("got SOA TTL %d, want the 1s left of its MINIMUM", ttl)
	}
	if opts := got.IsEdns0().Option; len(opts) != 0 {
		t.Errorf("got EDNS options %v, want the cookie removed", opts)
	}
}

func TestCache_Lifetime(t *testing.T) {
	soa := func(ttl, minttl uint32) *dns.SOA {
		return &dns.SOA{
			Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
			Ns:     "ns.example.com.",
			Mbox:   "admin.example.com.",
			Minttl: minttl,
		}
	}

	tests := []struct {
		name   string
		resp   func(q *dns.Msg) *dns.Msg
		cached bool
		ttl    uint32
	}{
		{name: "answer", resp: func(q *dns.Msg) *dns.Msg { return answer(q, 300) }, cached: true, ttl: 300},
		{name: "nxdomain uses SOA minimum", resp: func(q *dns.Msg) *dns.Msg {
			resp := new(dns.Msg).SetRcode(q, dns.RcodeNameError)
			resp.Ns = append(resp.Ns, soa(3600, 120))
			return resp
		}, cached: true, ttl: 120},
		{name: "servfail", resp: func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure) }},
		{name: "no records", resp: func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetReply(q) }},
		{name: "zero TTL", resp: func(q *dns.Msg) *dns.Msg { return answer(q, 0) }},
		{name: "truncated", resp: func(q *dns.Msg) *dns.Msg {
			resp := answer(q, 300)
			resp.Truncated = true
			return resp
		}},
		{name: "capped at MaxTTL", resp: func(q *dns.Msg) *dns.Msg { return answer(q, 7*24*3600) }, cached: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, clk := newTestCache(10)
			q := query("example.com.", dns.TypeA)
			c.Put(q, test.resp(q))

			if got := c.Get(q) != nil; got != test.cached {
				t.Fatalf("got cached=%t, want %t", got, test.cached)
			}
			if !test.cached {
				return
			}

			lifetime := time.Duration(test.ttl) * time.Second
			if test.ttl == 0 {
				lifetime = MaxTTL
			}
			clk.advance(lifetime - time.Second)
			if c.Get(q) == nil {
				t.Error("expired early")
			}
			clk.advance(time.Second)
			if c.Get(q) != nil {
				t.Error("still cached after its lifetime")
			}
		})
	}
}

func TestCache_EvictsLeastRecentlyUsed(t *testing.T) {
	c, _ := newTestCache(2)
	a, b, d := query("a.example.", dns.TypeA), query("b.example.", dns.TypeA), query("d.example.", dns.TypeA)

	c.Put(a, answer(a, 60))
	c.Put(b, answer(b, 60))
	c.Get(a) // a is now more recently used than b
	c.Put(d, answer(d, 60))

	if c.Get(b) != nil {
		t.Error("kept the least recently used entry")
	}
	if c.Get(a) == nil || c.Get(d) == nil {
		t.Error("evicted a recently used entry")
	}
	if c.Len() != 2 {
		t.Errorf("got %d entries, want 2", c.Len())
	}
}

func TestCache_Disabled(t *testing.T) {
	c, _ := newTestCache(0)
	q := query("example.com.", dns.TypeA)
	c.Put(q, answer(q, 60))

	if c.Get(q) != nil {
		t.Error("a zero-size cache cached a response")
	}
}

func BenchmarkCache_Get(b *testing.B) {
	c := New(10_000)
	q := query("example.com.", dns.TypeA)
	c.Put(q, answer(q, 3600))

	for b.Loop() {
		c.Get(q)
	}
}
