package hostnames

import (
	"context"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// Exchanger sends a DNS query and returns the response.
type Exchanger interface {
	Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error)
}

// PTR looks names up with reverse DNS ([RFC 1035, Section 3.5]), asking a
// resolver that knows the network's hostnames, typically the router:
// most home routers answer reverse lookups for their DHCP clients.
//
// [RFC 1035, Section 3.5]: https://www.rfc-editor.org/rfc/rfc1035.html#section-3.5
type PTR struct {
	Resolver Exchanger
}

// Lookup implements [Source].
func (p PTR) Lookup(ctx context.Context, addr netip.Addr) (string, error) {
	arpa, err := dns.ReverseAddr(addr.Unmap().String())
	if err != nil {
		return "", err
	}

	query := new(dns.Msg).SetQuestion(arpa, dns.TypePTR)
	resp, err := p.Resolver.Exchange(ctx, query)
	if err != nil {
		return "", err
	}
	for _, rr := range resp.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			return strings.TrimSuffix(ptr.Ptr, "."), nil
		}
	}
	return "", nil
}
