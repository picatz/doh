package doq

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/quic"
)

// Server defaults.
const (
	// DefaultMaxStreams bounds the queries one connection may have in
	// flight at once.
	DefaultMaxStreams = 100

	// DefaultIdleTimeout closes connections without traffic for this
	// long. RFC 9250, Section 5.5 suggests idle timeouts well over the
	// 30 seconds QUIC defaults to, so clients can reuse connections.
	DefaultIdleTimeout = 2 * time.Minute

	// queryTimeout bounds how long a client may take to send a query, and
	// to accept its response.
	queryTimeout = 10 * time.Second

	// shutdownTimeout bounds how long Serve waits for clients to
	// acknowledge their connections closing.
	shutdownTimeout = 5 * time.Second
)

// Request is a query a [Server] received.
type Request struct {
	// Query is the query. Its ID is zero, as DoQ requires on the wire.
	Query *dns.Msg

	// RemoteAddr is the client's address.
	RemoteAddr netip.AddrPort

	// ServerName is the TLS server name the client asked for, if any.
	ServerName string
}

// Handler answers a query. Returning nil answers with SERVFAIL.
type Handler func(ctx context.Context, r Request) *dns.Msg

// Server serves DoQ. Its fields must not change after Serve is called.
type Server struct {
	// TLSConfig provides the server's certificate. Serve uses a copy that
	// requires TLS 1.3, as QUIC does, and offers only the "doq" protocol.
	TLSConfig *tls.Config

	// Handler answers queries. It's called concurrently.
	Handler Handler

	// MaxStreams bounds the queries each connection may have in flight.
	// It defaults to DefaultMaxStreams.
	MaxStreams int64

	// IdleTimeout closes idle connections. It defaults to
	// DefaultIdleTimeout.
	IdleTimeout time.Duration

	// RequireAddressValidation makes clients prove they own their address
	// before the handshake, at the cost of a round trip, so spoofed
	// packets can't make the server do work for, or send data to, someone
	// else.
	RequireAddressValidation bool

	// Logger reports protocol errors. Nil discards them.
	Logger *slog.Logger
}

// Serve serves DoQ on pc until ctx is done, then closes every connection
// and returns.
func (s *Server) Serve(ctx context.Context, pc net.PacketConn) error {
	if s.TLSConfig == nil || s.Handler == nil {
		pc.Close()
		return errors.New("doq: Server needs a TLSConfig and a Handler")
	}
	logger := cmp.Or(s.Logger, slog.New(slog.DiscardHandler))

	tlsConfig := s.TLSConfig.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{ALPN}

	config := &quic.Config{
		TLSConfig:                tlsConfig,
		MaxBidiRemoteStreams:     cmp.Or(s.MaxStreams, DefaultMaxStreams),
		MaxUniRemoteStreams:      -1, // DoQ uses only bidirectional streams
		MaxIdleTimeout:           cmp.Or(s.IdleTimeout, DefaultIdleTimeout),
		RequireAddressValidation: s.RequireAddressValidation,
	}
	// A random reset key lets the server tell clients of connections it
	// forgot (as after a crash) to reconnect, rather than wait for an
	// idle timeout.
	if _, err := rand.Read(config.StatelessResetKey[:]); err != nil {
		pc.Close()
		return err
	}

	endpoint, err := quic.NewEndpoint(pc, config)
	if err != nil {
		pc.Close()
		return err
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	stop := context.AfterFunc(ctx, func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		_ = endpoint.Close(closeCtx)
	})
	defer stop()

	for {
		conn, err := endpoint.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() { s.serveConn(ctx, conn, logger) })
	}
}

// serveConn answers the queries on conn until it closes.
func (s *Server) serveConn(ctx context.Context, conn *quic.Conn, logger *slog.Logger) {
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != ALPN {
		// QUIC requires an application protocol, so this is a client
		// that didn't ask for DoQ.
		conn.Abort(closeError(CodeProtocolError, "doq: no application protocol"))
		return
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		wg.Go(func() {
			if err := s.serveStream(ctx, conn, stream, state.ServerName); errors.Is(err, errProtocol) {
				logger.Debug("doq: closing connection", slog.Any("remote", conn.RemoteAddr()), slog.Any("error", err))
				conn.Abort(closeError(CodeProtocolError, err.Error()))
			}
		})
	}
}

// serveStream answers the query on stream.
func (s *Server) serveStream(ctx context.Context, conn *quic.Conn, stream *quic.Stream, serverName string) error {
	defer stream.Close()

	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	stream.SetReadContext(ctx)
	stream.SetWriteContext(ctx)

	query, err := readMessage(stream)
	switch {
	case err != nil:
		stream.Reset(CodeProtocolError)
		return err
	case query.Id != 0:
		// RFC 9250, Section 4.2.1: the ID must be zero, since stream IDs
		// already match responses to queries.
		return errorf("query with nonzero ID %d", query.Id)
	case query.Response:
		return errorf("response sent as a query")
	case hasKeepalive(query):
		return errorf("query with edns-tcp-keepalive")
	}

	resp := s.Handler(ctx, Request{Query: query, RemoteAddr: conn.RemoteAddr(), ServerName: serverName})
	if resp == nil {
		resp = new(dns.Msg).SetRcode(query, dns.RcodeServerFailure)
	}
	resp.Id = 0
	if padded(query) {
		// Padding lives in EDNS(0), which a response to an EDNS query may
		// carry ([RFC 6891, Section 7]) even if the handler left it out.
		//
		// [RFC 6891, Section 7]: https://www.rfc-editor.org/rfc/rfc6891.html#section-7
		if resp.IsEdns0() == nil {
			resp.SetEdns0(dns.DefaultMsgSize, query.IsEdns0().Do())
		}
		pad(resp, responseBlock)
	}

	if err := writeMessage(stream, resp); err != nil {
		stream.Reset(CodeInternalError)
		return err
	}
	return nil
}

// errorf returns a protocol error.
func errorf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errProtocol}, args...)...)
}
