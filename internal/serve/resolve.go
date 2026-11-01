package serve

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/filter"
	"github.com/picatz/doh/internal/querylog"
	"github.com/picatz/doh/internal/upstream"
)

// request is a query, and what's known about who sent it.
type request struct {
	// transport is "doh", "udp", or "tcp".
	transport string
	query     *dns.Msg

	// client is the client's address, if known.
	client netip.Addr

	// profile and device name the client in the DoH path, if it did.
	profile, device string

	// trace, if set, collects the checks the query goes through, for an
	// explanation, which isn't logged or counted.
	trace *filter.Trace
}

// result is how a query was answered.
type result struct {
	resp            *dns.Msg
	decision        filter.Decision
	profile, device string
	tenant          string
	logged          bool
	cached          bool
	upstream        string
}

// resolve answers req within the configured timeout, counting and logging
// it.
func (s *Server) resolve(ctx context.Context, req request) (*dns.Msg, error) {
	res, err := s.answer(ctx, req)
	return res.resp, err
}

// answer answers req, counting and logging it unless it's traced.
func (s *Server) answer(ctx context.Context, req request) (result, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.config.Timeout))
	defer cancel()

	start := time.Now()
	res, err := s.decide(ctx, req)
	if req.trace != nil {
		return res, err
	}

	elapsed := time.Since(start)
	s.telemetry.observe(ctx, req.transport, elapsed, res.resp, err)
	if res.decision.Action == api.ActionBlock {
		s.telemetry.blockedReasons.Add(res.decision.Reason, 1)
		if res.decision.Source != "" {
			s.telemetry.blocked.Add(res.decision.Source, 1)
		}
	}
	s.log(req, res, err, elapsed)

	return res, err
}

// decide answers req under the client's profile.
func (s *Server) decide(ctx context.Context, req request) (result, error) {
	query := req.query
	q := query.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	engine := s.engine.Load()
	res := result{device: req.device, logged: true}

	var profile *filter.Profile
	if req.profile != "" {
		profile = engine.Profile(req.profile)
		if matched, device := engine.Match(req.client); profile != nil && matched == profile && res.device == "" {
			res.device = device
		}
	} else {
		profile, res.device = engine.Match(req.client)
	}

	if profile == nil {
		res.resp = filter.Refuse(query)
		res.decision.Action, res.decision.Reason = api.ActionRefuse, "refused"
		return res, nil
	}
	res.profile, res.tenant, res.logged = profile.ID(), profile.Tenant(), profile.Logged()

	switch q.Qclass {
	case dns.ClassINET:
	case dns.ClassCHAOS:
		res.resp = answerChaos(query, s.identity(res.profile, res.device, req.client))
		res.decision.Action, res.decision.Reason = api.ActionRewrite, filter.ReasonLocal
		return res, nil
	default:
		res.resp = new(dns.Msg).SetRcode(query, dns.RcodeNotImplemented)
		return res, nil
	}

	fq := filter.Query{Name: name, Type: q.Qtype, Client: req.client}
	d := profile.Check(ctx, fq, req.trace)
	res.decision = d

	switch d.Action {
	case api.ActionBlock:
		res.resp = profile.Block(query, d)
		return res, nil

	case api.ActionRewrite:
		res.resp = profile.Rewrite(query, d)
		if d.Target == "" {
			return res, nil
		}

		// Answer with the target's records, after the CNAME.
		target := query.Copy()
		target.Question[0].Name = d.Target
		resp, cached, up, err := s.forward(ctx, target)
		if err != nil {
			return res, err
		}
		res.resp.Authoritative = false
		res.resp.Rcode = resp.Rcode
		res.resp.Answer = append(res.resp.Answer, resp.Answer...)
		res.cached, res.upstream = cached, up
		return res, nil
	}

	if !s.forwarded(name) {
		if resp := answerLocal(query, name); resp != nil {
			req.trace.Add(filter.ReasonLocal, api.CheckMatch, "answered locally: special-use or private name")
			res.resp = resp
			res.decision = filter.Decision{Decision: api.Decision{Action: api.ActionRewrite, Reason: filter.ReasonLocal, Detail: "special-use or private name"}}
			return res, nil
		}
	}

	resp, cached, up, err := s.forward(ctx, query)
	if err != nil {
		return res, err
	}
	res.cached, res.upstream = cached, up

	if d.Reason != filter.ReasonAllow && d.Reason != filter.ReasonUpstream {
		if rd := profile.CheckResponse(fq, resp, req.trace); rd.Action == api.ActionBlock {
			res.decision = rd
			res.resp = profile.Block(query, rd)
			return res, nil
		}
	}

	res.resp = resp
	return res, nil
}

// forward answers query from the cache, or from the upstreams for its
// name, reporting whether it was cached and which upstream answered.
func (s *Server) forward(ctx context.Context, query *dns.Msg) (*dns.Msg, bool, string, error) {
	if s.cache != nil {
		if resp := s.cache.Get(query); resp != nil {
			s.telemetry.cacheHits.Add(1)
			return resp, true, "", nil
		}
		s.telemetry.cacheMisses.Add(1)
	}

	var answered string
	ctx = context.WithValue(ctx, upstreamKey{}, &answered)

	resp, err := s.exchangerFor(query.Question[0].Name).Exchange(ctx, query)
	if err != nil {
		// Rather than fail, answer with what the name recently resolved
		// to, if anything ([RFC 8767]), so a brief outage upstream
		// doesn't take the whole network's DNS down with it.
		//
		// [RFC 8767]: https://www.rfc-editor.org/rfc/rfc8767.html
		if s.cache != nil {
			if stale := s.cache.GetStale(query); stale != nil {
				s.telemetry.staleAnswers.Add(1)
				return withStaleEDE(query, stale), true, staleUpstream, nil
			}
		}
		return nil, false, "", err
	}
	if s.cache != nil {
		s.cache.Put(query, resp)
	}
	return resp, false, answered, nil
}

// staleUpstream is reported as the upstream of stale answers.
const staleUpstream = "stale cache"

// withStaleEDE marks a stale answer with an Extended DNS Error, for EDNS
// clients ([RFC 8914, Section 4.4]).
//
// [RFC 8914, Section 4.4]: https://www.rfc-editor.org/rfc/rfc8914.html#section-4.4
func withStaleEDE(query, resp *dns.Msg) *dns.Msg {
	opt := query.IsEdns0()
	if opt == nil {
		return resp
	}
	if resp.IsEdns0() == nil {
		resp.SetEdns0(dns.DefaultMsgSize, opt.Do())
	}
	resp.IsEdns0().Option = append(resp.IsEdns0().Option, &dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeStaleAnswer,
		ExtraText: "upstreams unreachable",
	})
	return resp
}

// upstreamKey is the context key under which [instrumented] exchangers
// record which upstream answered, in a *string.
type upstreamKey struct{}

// forwardZone is a domain whose names are sent to their own upstreams.
type forwardZone struct {
	domain    string
	exchanger upstream.Exchanger
}

// exchangerFor returns the upstreams for name: those of the most specific
// forward zone it's in, or the default upstreams.
func (s *Server) exchangerFor(name string) upstream.Exchanger {
	if z := s.forwardZoneOf(strings.ToLower(strings.TrimSuffix(name, "."))); z != nil {
		return z.exchanger
	}
	return s.exchanger
}

// forwardZoneOf returns the most specific forward zone name is in.
func (s *Server) forwardZoneOf(name string) *forwardZone {
	for d := name; ; {
		if z, ok := s.forwardZones[d]; ok {
			return z
		}
		_, parent, ok := strings.Cut(d, ".")
		if !ok {
			return nil
		}
		d = parent
	}
}

// forwarded reports whether name is in a forward zone.
func (s *Server) forwarded(name string) bool { return s.forwardZoneOf(name) != nil }

// identity is the TXT answer to "id.server" in the CHAOS class.
func (s *Server) identity(profile, device string, client netip.Addr) string {
	var b strings.Builder
	b.WriteString("doh")
	if profile != "" {
		b.WriteString(" profile=" + profile)
	}
	if device != "" {
		b.WriteString(" device=" + device)
	}
	if client.IsValid() {
		b.WriteString(" client=" + client.String())
	}
	return b.String()
}

// log records an answered query in the query log.
func (s *Server) log(req request, res result, err error, elapsed time.Duration) {
	if s.qlog == nil || !res.logged {
		return
	}

	q := req.query.Question[0]
	e := querylog.Entry{
		Time:       time.Now(),
		Profile:    res.profile,
		Tenant:     res.tenant,
		Device:     res.device,
		Transport:  req.transport,
		Name:       strings.ToLower(strings.TrimSuffix(q.Name, ".")),
		Type:       typeString(q.Qtype),
		Cached:     res.cached,
		Reason:     res.decision.Reason,
		Rule:       res.decision.Rule,
		Source:     res.decision.Source,
		Upstream:   res.upstream,
		DurationMS: float64(elapsed.Microseconds()) / 1000,
	}
	if req.client.IsValid() {
		e.Client = req.client.String()
	}

	switch {
	case err != nil:
		e.Status, e.Rcode = querylog.StatusError, dns.RcodeToString[dns.RcodeServerFailure]
		e.Rule = err.Error()
	case res.decision.Action == api.ActionBlock || res.decision.Action == api.ActionRefuse:
		e.Status, e.Rcode = querylog.StatusBlocked, dns.RcodeToString[res.resp.Rcode]
	case res.decision.Action == api.ActionRewrite:
		e.Status, e.Rcode, e.Answers = querylog.StatusRewritten, dns.RcodeToString[res.resp.Rcode], answers(res.resp)
	default:
		e.Status, e.Rcode, e.Answers = querylog.StatusAllowed, dns.RcodeToString[res.resp.Rcode], answers(res.resp)
	}
	if e.Status == querylog.StatusAllowed {
		e.Reason, e.Rule = "", "" // only explicit allows are worth noting
		if res.decision.Reason == filter.ReasonAllow {
			e.Reason, e.Rule = res.decision.Reason, res.decision.Rule
		}
	}
	if res.upstream == staleUpstream {
		e.Reason, e.Upstream = "stale", ""
	}

	s.qlog.Append(e)
}

// maxLoggedAnswers bounds the answers logged per query.
const maxLoggedAnswers = 8

// answers summarizes resp's answer records, such as "A 192.0.2.1".
func answers(resp *dns.Msg) []string {
	if resp == nil {
		return nil
	}
	var out []string
	for _, rr := range resp.Answer {
		if len(out) == maxLoggedAnswers {
			break
		}
		h := rr.Header()
		data := strings.TrimSpace(strings.TrimPrefix(rr.String(), h.String()))
		out = append(out, typeString(h.Rrtype)+" "+data)
	}
	return out
}

// typeString names a record type, such as "A", or "TYPE65280".
func typeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// clientAddr returns a DoH client's address: the connection's peer, or,
// if that's a trusted proxy, the address the proxy says it forwarded for.
//
// Proxies append to X-Forwarded-For, so the rightmost address not of a
// trusted proxy is the client; anything left of it could be forged.
func (s *Server) clientAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	addr = addr.Unmap().WithZone("")

	if !s.trustedProxy(addr) {
		return addr
	}

	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return addr // malformed: trust nothing further left
		}
		hop = hop.Unmap().WithZone("")
		if !s.trustedProxy(hop) {
			return hop
		}
		addr = hop
	}
	return addr
}

// trustedProxy reports whether addr is a trusted proxy.
func (s *Server) trustedProxy(addr netip.Addr) bool {
	for _, p := range s.trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// addrOf returns the address of a network peer.
func addrOf(a net.Addr) netip.Addr {
	switch a := a.(type) {
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap()
		}
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}
