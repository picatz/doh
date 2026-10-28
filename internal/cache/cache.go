// Package cache caches DNS responses for as long as their records live.
package cache

import (
	"container/list"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// MaxTTL caps how long any response is cached, however long its records'
// TTLs, so a misconfigured zone can't pin a stale answer for days.
const MaxTTL = 24 * time.Hour

// Cache is a bounded, least-recently-used cache of DNS responses, keyed by
// question and the header and EDNS bits (RD, AD, CD, EDNS, and DO) that
// change what a resolver returns. It's safe for concurrent use.
//
// Only standard queries are cached, and never ones carrying an EDNS Client
// Subnet option (RFC 7871), whose answers are tailored to the client.
type Cache struct {
	size int
	now  func() time.Time

	mu      sync.Mutex
	entries map[key]*list.Element
	lru     *list.List // of *entry, most recently used first
}

type key struct {
	name   string
	qtype  uint16
	qclass uint16

	rd, ad, cd bool // header flags
	edns, do   bool // EDNS (RFC 6891) and its DNSSEC OK bit
}

type entry struct {
	key     key
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

// New returns a cache holding up to size responses.
func New(size int) *Cache {
	return &Cache{
		size:    size,
		now:     time.Now,
		entries: make(map[key]*list.Element, size),
		lru:     list.New(),
	}
}

// keyOf returns the cache key for query, reporting whether it's cacheable:
// a standard query with one question and no EDNS Client Subnet option.
func keyOf(query *dns.Msg) (key, bool) {
	if query.Opcode != dns.OpcodeQuery || len(query.Question) != 1 {
		return key{}, false
	}

	q := query.Question[0]
	k := key{
		name:   strings.ToLower(q.Name),
		qtype:  q.Qtype,
		qclass: q.Qclass,
		rd:     query.RecursionDesired,
		ad:     query.AuthenticatedData,
		cd:     query.CheckingDisabled,
	}

	if opt := query.IsEdns0(); opt != nil {
		if slices.ContainsFunc(opt.Option, func(o dns.EDNS0) bool { return o.Option() == dns.EDNS0SUBNET }) {
			return key{}, false
		}
		k.edns, k.do = true, opt.Do()
	}

	return k, true
}

// Get returns a cached response to query, with its ID and question set to
// the query's, preserving the query's capitalization for clients that
// check it (DNS 0x20), and its TTLs reduced by the time it has been
// cached, or nil.
func (c *Cache) Get(query *dns.Msg) *dns.Msg {
	k, ok := keyOf(query)
	if !ok {
		return nil
	}

	c.mu.Lock()
	elem, ok := c.entries[k]
	if !ok {
		c.mu.Unlock()
		return nil
	}

	e := elem.Value.(*entry)
	now := c.now()
	if !now.Before(e.expires) {
		c.lru.Remove(elem)
		delete(c.entries, k)
		c.mu.Unlock()
		return nil
	}
	c.lru.MoveToFront(elem)
	c.mu.Unlock()

	resp := e.msg.Copy()
	resp.Id = query.Id
	resp.Question = slices.Clone(query.Question)
	decay(resp, uint32(now.Sub(e.stored)/time.Second))

	return resp
}

// Put caches resp as the answer to query, for the lifetime of its records.
// Failures, truncated responses, and responses without records aren't
// cached.
//
// The stored copy has its authority SOA TTL lowered to the SOA's MINIMUM,
// so hits advertise the negative answer's true remaining lifetime, and
// any DNS cookie (RFC 7873) removed, since it belongs to one client.
func (c *Cache) Put(query, resp *dns.Msg) {
	if c.size <= 0 || resp.Truncated {
		return
	}

	k, ok := keyOf(query)
	if !ok {
		return
	}

	ttl, ok := lifetime(resp)
	if !ok || ttl == 0 {
		return
	}

	msg := resp.Copy()
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			soa.Hdr.Ttl = min(soa.Hdr.Ttl, soa.Minttl)
		}
	}
	if opt := msg.IsEdns0(); opt != nil {
		opt.Option = slices.DeleteFunc(opt.Option, func(o dns.EDNS0) bool { return o.Option() == dns.EDNS0COOKIE })
	}

	now := c.now()
	e := &entry{
		key:     k,
		msg:     msg,
		stored:  now,
		expires: now.Add(min(time.Duration(ttl)*time.Second, MaxTTL)),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[k]; ok {
		elem.Value = e
		c.lru.MoveToFront(elem)
		return
	}

	c.entries[k] = c.lru.PushFront(e)

	for c.lru.Len() > c.size {
		oldest := c.lru.Back()
		c.lru.Remove(oldest)
		delete(c.entries, oldest.Value.(*entry).key)
	}
}

// Len returns the number of cached responses, including expired ones not
// yet evicted.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// lifetime returns how long resp may be cached: the smallest TTL of its
// records, with an authority SOA (which marks a negative answer) limited by
// its MINIMUM field, as RFC 2308, Section 5 describes. Only successful and
// NXDOMAIN responses with records are cacheable.
func lifetime(resp *dns.Msg) (uint32, bool) {
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return 0, false
	}

	ttl, found := uint32(math.MaxUint32), false

	for i, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}

			t := rr.Header().Ttl
			if soa, ok := rr.(*dns.SOA); ok && i == 1 {
				t = min(t, soa.Minttl)
			}

			ttl, found = min(ttl, t), true
		}
	}

	return ttl, found
}

// decay reduces the TTL of every record in msg by age seconds, to no less
// than zero, skipping the OPT pseudo-record whose TTL holds flags.
func decay(msg *dns.Msg, age uint32) {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if hdr := rr.Header(); hdr.Rrtype != dns.TypeOPT {
				hdr.Ttl -= min(hdr.Ttl, age)
			}
		}
	}
}
