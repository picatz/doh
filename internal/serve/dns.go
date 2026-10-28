package serve

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ServeDNS serves plain DNS on pc (UDP) and ln (TCP) until ctx is done,
// then shuts down gracefully, waiting for in-flight queries to finish.
//
// Queries are answered from the same upstreams as DoH queries. Messages
// that are themselves responses are dropped without a reply, as miekg/dns
// does by default, so two servers can't be made to answer each other in a
// loop. Responses over UDP are truncated to fit the client's advertised EDNS(0) buffer size
// (RFC 6891, Section 6.2.5), or 512 bytes without EDNS(0), setting the TC
// bit so the client retries over TCP.
func (s *Server) ServeDNS(ctx context.Context, pc net.PacketConn, ln net.Listener) error {
	// Let in-flight queries finish during shutdown, rather than failing
	// them as soon as ctx is done.
	queryCtx := context.WithoutCancel(ctx)

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := s.answerDNS(queryCtx, w.LocalAddr().Network(), req)

		if _, ok := w.LocalAddr().(*net.UDPAddr); ok {
			resp.Truncate(udpSize(req))
		}

		if err := w.WriteMsg(resp); err != nil {
			s.logger.Debug("dns: writing response", slog.Any("error", err))
		}
	})

	servers := []*dns.Server{
		// Accept queries up to the DNS message limit, such as EDNS-padded
		// ones, rather than the 512-byte default.
		{PacketConn: pc, Handler: handler, UDPSize: dns.MaxMsgSize},
		{Listener: ln, Handler: handler, ReadTimeout: readTimeout, WriteTimeout: readTimeout},
	}

	errc := make(chan error, len(servers))
	for i, srv := range servers {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }

		go func() { errc <- srv.ActivateAndServe() }()

		select {
		case <-started:
		case err := <-errc:
			return errors.Join(err, shutdownDNS(servers[:i]))
		}
	}

	s.logger.Info("serving dns",
		slog.String("udp", pc.LocalAddr().String()),
		slog.String("tcp", ln.Addr().String()),
	)

	if addrs := lanAddrs(pc.LocalAddr()); len(addrs) > 0 {
		s.logger.Info("set devices, or your router's DHCP DNS server setting, to this address to use it as their resolver",
			slog.Any("addrs", addrs),
		)
	}

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}

	s.logger.Info("shutting down dns", slog.Any("cause", context.Cause(ctx)))

	return errors.Join(err, shutdownDNS(servers))
}

// readTimeout bounds how long a TCP client may take to send a query.
const readTimeout = 10 * time.Second

// shutdownDNS gracefully stops servers, which must all have started,
// concurrently, so each stops accepting queries at once and shares the
// full grace period to drain.
func shutdownDNS(servers []*dns.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	errs := make([]error, len(servers))

	var wg sync.WaitGroup
	for i, srv := range servers {
		wg.Go(func() { errs[i] = srv.ShutdownContext(ctx) })
	}
	wg.Wait()

	return errors.Join(errs...)
}

// answerDNS returns the response to a plain DNS query received over
// transport ("udp" or "tcp"), replying with an
// error code rather than forwarding anything that isn't a single-question
// standard query.
func (s *Server) answerDNS(ctx context.Context, transport string, req *dns.Msg) *dns.Msg {
	switch {
	case req.Response:
		return new(dns.Msg).SetRcodeFormatError(req)
	case req.Opcode != dns.OpcodeQuery:
		return new(dns.Msg).SetRcode(req, dns.RcodeNotImplemented)
	case len(req.Question) != 1:
		return new(dns.Msg).SetRcodeFormatError(req)
	}

	resp, err := s.resolve(ctx, transport, req)
	if err != nil {
		s.logger.WarnContext(ctx, "dns: resolving failed",
			slog.String("name", req.Question[0].Name),
			slog.String("type", dns.TypeToString[req.Question[0].Qtype]),
			slog.Any("error", err),
		)
		return new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
	}

	resp.Id = req.Id
	return resp
}

// udpSize returns the largest UDP response the client accepts.
func udpSize(req *dns.Msg) int {
	if opt := req.IsEdns0(); opt != nil {
		return max(int(opt.UDPSize()), dns.MinMsgSize)
	}

	return dns.MinMsgSize
}

// lanAddrs returns the private network addresses clients can reach the
// DNS listener at: its own address, or every private interface address if
// it listens on all of them.
func lanAddrs(listen net.Addr) []netip.Addr {
	ap, err := netip.ParseAddrPort(listen.String())
	if err != nil {
		return nil
	}

	if !ap.Addr().IsUnspecified() {
		if ap.Addr().IsPrivate() {
			return []netip.Addr{ap.Addr()}
		}
		return nil
	}

	ifaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	var addrs []netip.Addr
	for _, a := range ifaceAddrs {
		prefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}

		// An IPv4 listener on all addresses only accepts IPv4 clients.
		addr := prefix.Addr()
		if addr.IsPrivate() && (ap.Addr().Is6() || addr.Is4()) {
			addrs = append(addrs, addr)
		}
	}

	slices.SortFunc(addrs, netip.Addr.Compare)
	return addrs
}
