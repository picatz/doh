package serve

import (
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/filter"
)

// localZones are zones the server answers itself rather than forwarding,
// because their names mean nothing on the public internet, and asking
// upstream would leak details of the local network or let clients
// discover resolvers that bypass this one:
//
//   - localhost names resolve to loopback ([RFC 6761, Section 6.3]).
//   - invalid names don't exist ([RFC 6761, Section 6.4]).
//   - local is for Multicast DNS, not unicast resolvers ([RFC 6762,
//     Section 3]).
//   - home.arpa is for home networks ([RFC 8375, Section 4]).
//   - resolver.arpa is how clients discover a resolver's encrypted
//     endpoints, which forwarders must not ask upstream about, since the
//     upstream's answer would point clients past this resolver ([RFC 9462,
//     Section 6.5]).
//   - Reverse zones for private and special-purpose addresses
//     ([RFC 6303, Section 4]), and for shared address space ([RFC 7793]).
//
// Zones covered by a forward zone, such as "168.192.in-addr.arpa" or
// "home.arpa" sent to the router, are forwarded instead.
//
// [RFC 6761, Section 6.3]: https://www.rfc-editor.org/rfc/rfc6761.html#section-6.3
// [RFC 6761, Section 6.4]: https://www.rfc-editor.org/rfc/rfc6761.html#section-6.4
// [RFC 6762, Section 3]: https://www.rfc-editor.org/rfc/rfc6762.html#section-3
// [RFC 8375, Section 4]: https://www.rfc-editor.org/rfc/rfc8375.html#section-4
// [RFC 9462, Section 6.5]: https://www.rfc-editor.org/rfc/rfc9462.html#section-6.5
// [RFC 6303, Section 4]: https://www.rfc-editor.org/rfc/rfc6303.html#section-4
// [RFC 7793]: https://www.rfc-editor.org/rfc/rfc7793.html
var localZones = func() map[string]localZone {
	zones := map[string]localZone{
		"localhost":     zoneLoopback,
		"invalid":       zoneNXDomain,
		"local":         zoneNXDomain,
		"home.arpa":     zoneNXDomain,
		"resolver.arpa": zoneNoData,

		// RFC 6303, Section 4.2 and 4.3: IPv4.
		"10.in-addr.arpa":              zoneNXDomain,
		"168.192.in-addr.arpa":         zoneNXDomain,
		"0.in-addr.arpa":               zoneNXDomain,
		"127.in-addr.arpa":             zoneNXDomain,
		"254.169.in-addr.arpa":         zoneNXDomain,
		"2.0.192.in-addr.arpa":         zoneNXDomain,
		"100.51.198.in-addr.arpa":      zoneNXDomain,
		"113.0.203.in-addr.arpa":       zoneNXDomain,
		"255.255.255.255.in-addr.arpa": zoneNXDomain,

		// RFC 6303, Section 4.4 to 4.6: IPv6 unspecified, loopback,
		// unique local (fc00::/7), and link-local (fe80::/10).
		"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa": zoneNXDomain,
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa": zoneNXDomain,
		"c.f.ip6.arpa":             zoneNXDomain,
		"d.f.ip6.arpa":             zoneNXDomain,
		"8.e.f.ip6.arpa":           zoneNXDomain,
		"9.e.f.ip6.arpa":           zoneNXDomain,
		"a.e.f.ip6.arpa":           zoneNXDomain,
		"b.e.f.ip6.arpa":           zoneNXDomain,
		"8.b.d.0.1.0.0.2.ip6.arpa": zoneNXDomain, // documentation, 2001:db8::/32
	}
	for i := 16; i <= 31; i++ {
		zones[strconv.Itoa(i)+".172.in-addr.arpa"] = zoneNXDomain
	}
	for i := 64; i <= 127; i++ {
		zones[strconv.Itoa(i)+".100.in-addr.arpa"] = zoneNXDomain
	}
	return zones
}()

// localZone is how a local zone is answered.
type localZone int

const (
	zoneNXDomain localZone = iota // no names exist
	zoneNoData                    // names exist, with no records
	zoneLoopback                  // every name is loopback
)

// localZoneOf returns the local zone name is in, if any.
func localZoneOf(name string) (string, localZone, bool) {
	for d := name; ; {
		if z, ok := localZones[d]; ok {
			return d, z, true
		}
		_, parent, ok := strings.Cut(d, ".")
		if !ok {
			return "", 0, false
		}
		d = parent
	}
}

// answerLocal answers query if it's for a local zone, returning nil if
// it isn't.
func answerLocal(query *dns.Msg, name string) *dns.Msg {
	zone, kind, ok := localZoneOf(name)
	if !ok {
		return nil
	}

	resp := new(dns.Msg).SetReply(query)
	resp.Authoritative, resp.RecursionAvailable = true, true

	q := query.Question[0]
	switch {
	case kind == zoneLoopback && q.Qtype == dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{Hdr: rrHeader(q.Name, dns.TypeA), A: net.IPv4(127, 0, 0, 1)})
	case kind == zoneLoopback && q.Qtype == dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: rrHeader(q.Name, dns.TypeAAAA), AAAA: net.IPv6loopback})
	case kind == zoneNXDomain && name != zone:
		resp.Rcode = dns.RcodeNameError
		resp.Ns = append(resp.Ns, filter.SOA(zone))
	default:
		resp.Ns = append(resp.Ns, filter.SOA(zone))
	}
	return resp
}

func rrHeader(name string, rrtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: filter.BlockedTTL}
}

// answerChaos answers CHAOS-class queries for the server's identity
// ([RFC 4892, Section 2]): "id.server" and "hostname.bind" with a TXT
// record naming the server and the client's profile, which lets "doh
// doctor" (or `dig CH TXT id.server`) confirm queries reach this server;
// "version.server" and "version.bind" with just "doh", rather than a
// version that would help attackers; and anything else with REFUSED.
//
// [RFC 4892, Section 2]: https://www.rfc-editor.org/rfc/rfc4892.html#section-2
func answerChaos(query *dns.Msg, identity string) *dns.Msg {
	q := query.Question[0]
	name := strings.ToLower(q.Name)

	var txt string
	switch name {
	case "id.server.", "hostname.bind.":
		txt = identity
	case "version.server.", "version.bind.":
		txt = "doh"
	default:
		return new(dns.Msg).SetRcode(query, dns.RcodeRefused)
	}

	resp := new(dns.Msg).SetReply(query)
	resp.Authoritative = true
	if q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY {
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0},
			Txt: []string{txt},
		})
	}
	return resp
}
