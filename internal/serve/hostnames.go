package serve

import (
	"context"
	"log/slog"
	"strings"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/hostnames"
	"github.com/picatz/doh/internal/upstream"
)

// configureHostnames starts learning device names, from, in order: DHCP
// lease files; the resolvers of forward zones covering a client's reverse
// zone, such as "168.192.in-addr.arpa" forwarded to the router; the
// configured resolvers; and with none configured, the default gateway.
func (s *Server) configureHostnames() error {
	c := s.config.DeviceNames
	if c.Disabled {
		return nil
	}

	var sources []hostnames.Source
	for _, path := range c.Leases {
		sources = append(sources, &hostnames.Leases{Path: path})
	}

	sources = append(sources, hostnames.PTR{Resolver: forwardedReverse{s}})

	resolvers := c.Resolvers
	if len(resolvers) == 0 {
		if gw, ok := hostnames.DefaultGateway(); ok && hostnames.IsLocal(gw) {
			resolvers = []string{gw.String()}
			s.logger.Debug("device names: asking the default gateway", slog.String("gateway", gw.String()))
		}
	}
	if len(resolvers) > 0 {
		var exchangers []upstream.Exchanger
		for _, r := range resolvers {
			e, err := upstream.Parse(r, upstream.Options{})
			if err != nil {
				return err
			}
			exchangers = append(exchangers, e)
		}
		sources = append(sources, hostnames.PTR{Resolver: upstream.NewPool(exchangers)})
	}

	s.hostnames = hostnames.New(sources)
	return nil
}

// forwardedReverse answers reverse lookups through the forward zone that
// covers them, if any, so a forward zone such as "168.192.in-addr.arpa"
// sent to the router names the router's clients too. Names in no forward
// zone get no answer: they're never sent to the public upstreams.
type forwardedReverse struct{ s *Server }

func (f forwardedReverse) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	name := strings.ToLower(strings.TrimSuffix(q.Question[0].Name, "."))
	if z := f.s.forwardZoneOf(name); z != nil {
		return z.exchanger.Exchange(ctx, q)
	}
	return new(dns.Msg).SetRcode(q, dns.RcodeNameError), nil
}
