package serve

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/doq"
)

// ServeDoQ serves DNS-over-QUIC ([RFC 9250]) on pc until ctx is done, with
// the same certificate as DoH and DoT. As over DoT, the TLS server name
// the client asked for selects its profile and device.
//
// DoQ support is experimental: it's built on golang.org/x/net/quic, which
// isn't yet considered ready for production by its authors.
//
// [RFC 9250]: https://www.rfc-editor.org/rfc/rfc9250.html
func (s *Server) ServeDoQ(ctx context.Context, pc net.PacketConn) error {
	if s.tlsConfig == nil {
		pc.Close()
		return errors.New("serve: DoQ needs a TLS certificate or an ACME domain")
	}

	// Let in-flight queries finish during shutdown.
	queryCtx := context.WithoutCancel(ctx)

	srv := &doq.Server{
		TLSConfig: s.tlsConfig,
		Logger:    s.logger,
		Handler: func(_ context.Context, r doq.Request) *dns.Msg {
			return s.answerByServerName(queryCtx, "doq", r.RemoteAddr.Addr().Unmap(), r.ServerName, r.Query)
		},
	}

	s.setListener("doq", pc.LocalAddr())
	s.logger.Info("serving doq (experimental)", slog.String("addr", pc.LocalAddr().String()), slog.String("hostname", s.config.Hostname))

	err := srv.Serve(ctx, pc)
	s.logger.Info("shutting down doq", slog.Any("cause", context.Cause(ctx)))
	return err
}
